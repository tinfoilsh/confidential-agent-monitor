package session

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

var SFTPDefinition = connector.Definition{HostKey: true, NewConfig: func() connector.Server { return new(SFTP) }, Requests: []connector.Request{new(SSHRequest), new(SFTPRequest)}}

// SFTP terminates the SSH subsystem and mediates SFTP v3 requests. Root is
// presented as / to clients. Use a server-side chroot when other writers can
// replace upstream directories concurrently with path resolution.
type SFTP struct {
	SSH
	Root string `json:"root"`
}

const maxSFTPPacket = 1 << 20

func (t *SFTP) Serve(s *connector.Stream, e *connector.Env) {
	t.serve(s, e, func(up *ssh.Client, nc ssh.NewChannel) {
		if nc.ChannelType() != channelSession {
			nc.Reject(ssh.Prohibited, "only SFTP sessions are supported")
			return
		}
		ch, requests, err := nc.Accept()
		if err != nil {
			return
		}
		defer ch.Close()
		for r := range requests {
			var subsystem struct{ Name string }
			if r.Type != "subsystem" || ssh.Unmarshal(r.Payload, &subsystem) != nil || subsystem.Name != "sftp" {
				if r.WantReply {
					r.Reply(false, nil)
				}
				continue
			}
			session, err := up.NewSession()
			if err != nil {
				r.Reply(false, nil)
				return
			}
			defer session.Close()
			reader, err := session.StdoutPipe()
			if err != nil {
				r.Reply(false, nil)
				return
			}
			writer, err := session.StdinPipe()
			if err != nil {
				r.Reply(false, nil)
				return
			}
			if err := session.RequestSubsystem("sftp"); err != nil {
				r.Reply(false, nil)
				return
			}
			if r.WantReply {
				r.Reply(true, nil)
			}
			go ssh.DiscardRequests(requests)
			p := sftpProxy{up: reader, out: writer, gate: func(r connector.Request) error { return s.Gate(r) }, handles: map[string]*sftpHandle{}}
			p.serve(ch, cmp.Or(t.Root, "/"))
			return
		}
	})
}

type sftpHandle struct {
	remote                 string
	path                   string
	read, write, directory bool
}

type sftpProxy struct {
	up      io.Reader
	out     io.Writer
	gate    func(connector.Request) error
	root    string
	handles map[string]*sftpHandle
	next    uint64
	broken  bool
}

func sftpRead(r io.Reader) ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > maxSFTPPacket {
		return nil, errors.New("invalid SFTP packet length")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func sftpWrite(w io.Writer, b []byte) error {
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(b)))
	_, err := io.Copy(w, io.MultiReader(bytes.NewReader(head[:]), bytes.NewReader(b)))
	return err
}

func sftpString(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}

type sftpDecoder struct {
	b   []byte
	err bool
}

func (d *sftpDecoder) take(n int) []byte {
	if n < 0 || n > len(d.b) {
		d.err = true
		return nil
	}
	b := d.b[:n]
	d.b = d.b[n:]
	return b
}
func (d *sftpDecoder) u32() uint32 {
	b := d.take(4)
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (d *sftpDecoder) u64() uint64 {
	b := d.take(8)
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (d *sftpDecoder) str() string { return string(d.take(int(d.u32()))) }
func (d *sftpDecoder) attrs() map[string]uint64 {
	a := map[string]uint64{}
	f := d.u32()
	if f & ^uint32(15) != 0 {
		d.err = true
		return a
	}
	if f&1 != 0 {
		a["size"] = d.u64()
	}
	if f&2 != 0 {
		a["uid"], a["gid"] = uint64(d.u32()), uint64(d.u32())
	}
	if f&4 != 0 {
		a["permissions"] = uint64(d.u32())
	}
	if f&8 != 0 {
		a["atime"], a["mtime"] = uint64(d.u32()), uint64(d.u32())
	}
	return a
}

func sftpStatus(id uint32, code uint32, message string) []byte {
	b := binary.BigEndian.AppendUint32([]byte{101}, id)
	b = binary.BigEndian.AppendUint32(b, code)
	b = append(b, sftpString(message)...)
	return append(b, sftpString("")...)
}

func (p *sftpProxy) rpc(b []byte) ([]byte, error) {
	if err := sftpWrite(p.out, b); err != nil {
		p.broken = true
		return nil, err
	}
	r, err := sftpRead(p.up)
	if err != nil {
		p.broken = true
		return nil, err
	}
	if len(r) < 5 || len(b) < 5 || !bytes.Equal(r[1:5], b[1:5]) {
		p.broken = true
		return nil, errors.New("invalid SFTP response")
	}
	return r, nil
}

func (p *sftpProxy) realpath(name string) (string, error) {
	r, err := p.rpc(append([]byte{16, 0, 0, 0, 0}, sftpString(name)...))
	if err != nil {
		return "", err
	}
	if r[0] != 104 {
		return "", errors.New("cannot resolve SFTP path")
	}
	d := sftpDecoder{b: r[5:]}
	if d.u32() != 1 {
		return "", errors.New("invalid SFTP realpath")
	}
	v := d.str()
	if d.err || !path.IsAbs(v) || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
		return "", errors.New("invalid SFTP realpath")
	}
	return path.Clean(v), nil
}

func (p *sftpProxy) serve(client io.ReadWriter, root string) error {
	init, err := sftpRead(client)
	if err != nil {
		return err
	}
	if len(init) != 5 || init[0] != 1 || binary.BigEndian.Uint32(init[1:]) < 3 {
		return errors.New("SFTP v3 required")
	}
	if err := sftpWrite(p.out, []byte{1, 0, 0, 0, 3}); err != nil {
		return err
	}
	version, err := sftpRead(p.up)
	if err != nil {
		return err
	}
	if len(version) < 5 || version[0] != 2 || binary.BigEndian.Uint32(version[1:5]) != 3 {
		return errors.New("upstream must support SFTP v3")
	}
	p.root, err = p.realpath(root)
	if err != nil {
		return err
	}
	p.root, err = p.canonical(p.root, false, false)
	if err != nil {
		return err
	}
	// Do not advertise upstream extensions that bypass the request checks.
	if err := sftpWrite(client, []byte{2, 0, 0, 0, 3}); err != nil {
		return err
	}
	for {
		b, err := sftpRead(client)
		if err != nil {
			return err
		}
		if len(b) < 5 {
			return errors.New("short SFTP request")
		}
		id := binary.BigEndian.Uint32(b[1:5])
		out, err := p.request(b)
		if p.broken {
			return errors.New("SFTP upstream disconnected")
		}
		if err != nil {
			out = sftpStatus(id, 3, "SFTP operation refused")
		}
		if err := sftpWrite(client, out); err != nil {
			return err
		}
	}
}

// Resolve existing objects, or their parent for entry operations such as remove
// and rename. A symlink cannot move a checked path outside the account root.
func (p *sftpProxy) resolve(name string, entry, create bool) (string, error) {
	if !utf8.ValidString(name) || strings.ContainsRune(name, 0) {
		return "", errors.New("invalid path")
	}
	v := path.Join(p.root, path.Clean("/"+name))
	resolved, err := p.canonical(v, entry, create || entry)
	if err != nil {
		return "", err
	}
	if resolved != p.root && !strings.HasPrefix(resolved, strings.TrimSuffix(p.root, "/")+"/") {
		return "", errors.New("path leaves SFTP root")
	}
	return resolved, nil
}

// Some SFTP servers only clean REALPATH lexically. Resolve each component with
// LSTAT and READLINK rather than treating that response as proof of containment.
func (p *sftpProxy) canonical(name string, entry, create bool) (string, error) {
	for links := 0; links <= 40; links++ {
		parts := strings.Split(strings.TrimPrefix(path.Clean(name), "/"), "/")
		current, restart := "/", false
		for i, part := range parts {
			if part == "" {
				continue
			}
			current = path.Join(current, part)
			last := i == len(parts)-1
			if last && entry {
				return current, nil
			}
			r, err := p.rpc(append([]byte{7, 0, 0, 0, 0}, sftpString(current)...))
			if err != nil {
				return "", err
			}
			if r[0] == 101 && len(r) >= 9 && binary.BigEndian.Uint32(r[5:9]) == 2 && last && create {
				return current, nil
			}
			if r[0] != 105 {
				return "", errors.New("cannot inspect SFTP path")
			}
			d := sftpDecoder{b: r[5:]}
			flags := d.u32()
			if flags&1 != 0 {
				d.take(8)
			}
			if flags&2 != 0 {
				d.take(8)
			}
			mode := d.u32()
			if d.err || flags&4 == 0 {
				return "", errors.New("SFTP server omitted file type")
			}
			if mode&0170000 != 0120000 {
				continue
			}
			r, err = p.rpc(append([]byte{19, 0, 0, 0, 0}, sftpString(current)...))
			if err != nil {
				return "", err
			}
			if r[0] != 104 {
				return "", errors.New("cannot read SFTP symlink")
			}
			d = sftpDecoder{b: r[5:]}
			if d.u32() != 1 {
				return "", errors.New("invalid SFTP symlink")
			}
			target := d.str()
			if d.err || target == "" || !utf8.ValidString(target) || strings.ContainsRune(target, 0) {
				return "", errors.New("invalid SFTP symlink")
			}
			if !path.IsAbs(target) {
				target = path.Join(path.Dir(current), target)
			}
			name = path.Join(target, path.Join(parts[i+1:]...))
			restart = true
			break
		}
		if !restart {
			return current, nil
		}
	}
	return "", errors.New("too many SFTP symlinks")
}

func (p *sftpProxy) virtual(name string) string {
	return "/" + strings.TrimPrefix(strings.TrimPrefix(name, p.root), "/")
}

func (p *sftpProxy) check(e SFTPRequest) error { return p.gate(&e) }

func (p *sftpProxy) request(b []byte) ([]byte, error) {
	id := binary.BigEndian.Uint32(b[1:5])
	d := sftpDecoder{b: b[5:]}
	e := SFTPRequest{}
	var h *sftpHandle
	var handle, name, target string
	var tail []byte
	entry, create := false, false
	switch b[0] {
	case 3: // OPEN
		e.Command, name = "open", d.str()
		tail = d.b
		e.Flags = d.u32()
		e.Attributes = d.attrs()
		e.Read, e.Write = e.Flags&1 != 0, e.Flags&2 != 0
		if e.Flags & ^uint32(63) != 0 || !e.Read && !e.Write || e.Flags&60 != 0 && !e.Write {
			d.err = true
		}
		create = e.Flags&8 != 0
	case 7, 9, 11, 13, 14, 15, 16, 17, 18:
		e.Command = map[byte]string{7: "lstat", 9: "setstat", 11: "opendir", 13: "remove", 14: "mkdir", 15: "rmdir", 16: "realpath", 17: "stat", 18: "rename"}[b[0]]
		name = d.str()
		entry = b[0] == 7 || b[0] == 13 || b[0] == 14 || b[0] == 15 || b[0] == 18
		if b[0] == 18 {
			target = d.str()
		}
		if b[0] == 9 || b[0] == 14 {
			tail = d.b
			e.Attributes = d.attrs()
		}
	case 4, 5, 6, 8, 10, 12:
		e.Command = map[byte]string{4: "close", 5: "read", 6: "write", 8: "fstat", 10: "fsetstat", 12: "readdir"}[b[0]]
		handle = d.str()
		h = p.handles[handle]
		if h == nil {
			return sftpStatus(id, 4, "unknown file handle"), nil
		}
		tail = d.b
		switch b[0] {
		case 5:
			e.Offset, e.Size = d.u64(), d.u32()
			if !h.read || h.directory || e.Size > maxSFTPPacket-9 {
				d.err = true
			}
		case 6:
			e.Offset = d.u64()
			data := d.str()
			e.Size = uint32(len(data))
			if !h.write || h.directory {
				d.err = true
			}
		case 10:
			e.Attributes = d.attrs()
		case 12:
			if !h.directory {
				d.err = true
			}
		}
	default:
		return sftpStatus(id, 8, "unsupported SFTP operation"), nil
	}
	if d.err || len(d.b) != 0 {
		return sftpStatus(id, 5, "malformed SFTP request"), nil
	}
	if (b[0] == 3 || b[0] == 11) && len(p.handles) >= 1024 {
		return sftpStatus(id, 4, "too many open handles"), nil
	}
	if h != nil {
		name = h.path
	} else {
		// Check the requested name before resolving it, then the canonical name.
		e.Path = path.Clean("/" + name)
		if target != "" {
			e.Target = path.Clean("/" + target)
		}
		if err := p.check(e); err != nil {
			return nil, err
		}
		var err error
		name, err = p.resolve(name, entry, create)
		if err != nil {
			return nil, err
		}
		if b[0] == 18 {
			target, err = p.resolve(target, true, true)
			if err != nil {
				return nil, err
			}
		}
	}
	e.Path = p.virtual(name)
	if target != "" {
		e.Target = p.virtual(target)
	}
	if e.Command != "close" {
		if err := p.check(e); err != nil {
			return nil, err
		}
	}
	if b[0] == 16 {
		r := binary.BigEndian.AppendUint32([]byte{104}, id)
		r = binary.BigEndian.AppendUint32(r, 1)
		r = append(r, sftpString(e.Path)...)
		r = append(r, sftpString(e.Path)...)
		return binary.BigEndian.AppendUint32(r, 0), nil
	}
	request := append([]byte(nil), b[:5]...)
	if h != nil {
		request = append(request, sftpString(h.remote)...)
	} else {
		request = append(request, sftpString(name)...)
	}
	if b[0] == 18 {
		request = append(request, sftpString(target)...)
	}
	request = append(request, tail...)
	r, err := p.rpc(request)
	if err != nil {
		return nil, err
	}
	if r[0] == 102 && (b[0] == 3 || b[0] == 11) {
		d := sftpDecoder{b: r[5:]}
		remote := d.str()
		if d.err || len(d.b) != 0 {
			return nil, errors.New("invalid handle")
		}
		p.next++
		local := fmt.Sprint(p.next)
		p.handles[local] = &sftpHandle{remote: remote, path: name, read: e.Read, write: e.Write, directory: b[0] == 11}
		return append(r[:5], sftpString(local)...), nil
	}
	if r[0] == 101 && len(r) >= 9 && binary.BigEndian.Uint32(r[5:9]) == 0 {
		if b[0] == 4 {
			delete(p.handles, handle)
		}
		if b[0] == 18 {
			for _, h := range p.handles {
				if h.path == name || strings.HasPrefix(h.path, name+"/") {
					h.path = target + strings.TrimPrefix(h.path, name)
				}
			}
		}
	}
	return r, nil
}

type SFTPRequest facts.SFTP

func (v *SFTPRequest) Describe(c connector.Context) (facts.Facts, error) {
	details := facts.Details{SFTP: (*facts.SFTP)(v)}
	action := map[string]string{
		"read": "read", "stat": "read", "lstat": "read", "fstat": "read", "opendir": "read", "readdir": "read", "realpath": "read", "readlink": "read",
		"write": "write", "mkdir": "write", "remove": "delete", "rmdir": "delete", "rename": "rename", "setstat": "metadata", "fsetstat": "metadata", "close": "session",
	}[v.Command]
	if v.Command == "open" {
		switch {
		case v.Read && v.Write:
			action = "readwrite"
		case v.Read:
			action = "read"
		case v.Write:
			action = "write"
		}
	}
	scope, _ := facts.JSON[map[string]any](v)
	delete(scope, "command")
	delete(scope, "offset")
	delete(scope, "size")
	var effects []string
	if action == "session" {
		effects = []string{"session"}
	}
	op := &facts.Operation{ID: v.Command, Action: action, Effects: effects}
	return facts.Facts{Operation: op, Title: "SFTP " + v.Command + " " + v.Path, Parameters: scope, Details: details}, nil
}
