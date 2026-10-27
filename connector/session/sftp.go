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

var SFTPKind = connector.Kind{UsesHostKey: true, Parse: parseSFTP, New: func() connector.Server { return new(SFTP) }}

// SFTP terminates the SSH subsystem and mediates SFTP v3 requests. Root is
// presented as / to clients. Use a server-side chroot when other writers can
// replace upstream directories concurrently with path resolution.
type sftpSetup struct {
	sshSetup
	Root string `json:"root"`
}

const maxSFTPPacket = 1 << 20

// SFTP v3 packet types and status codes, from draft-ietf-secsh-filexfer-02.
func parseSFTP(source connector.Setup) (connector.Prepared, error) {
	c := new(sftpSetup)
	if err := connector.ParseSetup(source, c, &c.Semantics, &c.Semantics); err != nil {
		return connector.Prepared{}, err
	}
	names, err := c.Declarations("key")
	return connector.Prepared{Source: source, Value: c, SecretNames: names}, err
}

// SFTP keeps one immutable setup for each admitted stream.
type SFTP struct{ connector.Slot[sftpSetup] }

const (
	sftpVersion = 3

	fxpInit     = 1
	fxpVersion  = 2
	fxpOpen     = 3
	fxpClose    = 4
	fxpRead     = 5
	fxpWrite    = 6
	fxpLstat    = 7
	fxpFstat    = 8
	fxpSetstat  = 9
	fxpFsetstat = 10
	fxpOpendir  = 11
	fxpReaddir  = 12
	fxpRemove   = 13
	fxpMkdir    = 14
	fxpRmdir    = 15
	fxpRealpath = 16
	fxpStat     = 17
	fxpRename   = 18
	fxpReadlink = 19
	fxpStatus   = 101
	fxpHandle   = 102
	fxpName     = 104
	fxpAttrs    = 105

	fxOK               = 0
	fxNoSuchFile       = 2
	fxPermissionDenied = 3
	fxFailure          = 4
	fxBadMessage       = 5
	fxOpUnsupported    = 8
)

func (owner *SFTP) Serve(s *connector.Stream, e *connector.Env) {
	captured := owner.Load()
	if captured == nil {
		return
	}
	t := captured.Value
	t.Secrets = captured.Secrets

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
			p := sftpProxy{up: reader, out: writer, check: func(r *SFTPRequest) error { return s.Gate(s.Context, t.Capture((r).Describe())) }, handles: map[string]*sftpHandle{}}
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
	check   func(*SFTPRequest) error
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
	b := binary.BigEndian.AppendUint32([]byte{fxpStatus}, id)
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
	r, err := p.rpc(append([]byte{fxpRealpath, 0, 0, 0, 0}, sftpString(name)...))
	if err != nil {
		return "", err
	}
	if r[0] != fxpName {
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
	if len(init) != 5 || init[0] != fxpInit || binary.BigEndian.Uint32(init[1:]) < sftpVersion {
		return errors.New("SFTP v3 required")
	}
	if err := sftpWrite(p.out, []byte{fxpInit, 0, 0, 0, sftpVersion}); err != nil {
		return err
	}
	version, err := sftpRead(p.up)
	if err != nil {
		return err
	}
	if len(version) < 5 || version[0] != fxpVersion || binary.BigEndian.Uint32(version[1:5]) != sftpVersion {
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
	if err := sftpWrite(client, []byte{fxpVersion, 0, 0, 0, sftpVersion}); err != nil {
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
			out = sftpStatus(id, fxPermissionDenied, "SFTP operation refused")
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
			r, err := p.rpc(append([]byte{fxpLstat, 0, 0, 0, 0}, sftpString(current)...))
			if err != nil {
				return "", err
			}
			if r[0] == fxpStatus && len(r) >= 9 && binary.BigEndian.Uint32(r[5:9]) == fxNoSuchFile && last && create {
				return current, nil
			}
			if r[0] != fxpAttrs {
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
			r, err = p.rpc(append([]byte{fxpReadlink, 0, 0, 0, 0}, sftpString(current)...))
			if err != nil {
				return "", err
			}
			if r[0] != fxpName {
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

func (p *sftpProxy) request(b []byte) ([]byte, error) {
	id := binary.BigEndian.Uint32(b[1:5])
	d := sftpDecoder{b: b[5:]}
	e := SFTPRequest{}
	var h *sftpHandle
	var handle, name, target string
	var tail []byte
	entry, create := false, false
	switch b[0] {
	case fxpOpen:
		e.Command, name = "open", d.str()
		tail = d.b
		e.Flags = d.u32()
		e.Attributes = d.attrs()
		e.Read, e.Write = e.Flags&1 != 0, e.Flags&2 != 0
		if e.Flags & ^uint32(63) != 0 || !e.Read && !e.Write || e.Flags&60 != 0 && !e.Write {
			d.err = true
		}
		create = e.Flags&8 != 0
	case fxpLstat, fxpSetstat, fxpOpendir, fxpRemove, fxpMkdir, fxpRmdir, fxpRealpath, fxpStat, fxpRename:
		e.Command = map[byte]string{fxpLstat: "lstat", fxpSetstat: "setstat", fxpOpendir: "opendir", fxpRemove: "remove", fxpMkdir: "mkdir", fxpRmdir: "rmdir", fxpRealpath: "realpath", fxpStat: "stat", fxpRename: "rename"}[b[0]]
		name = d.str()
		entry = b[0] == fxpLstat || b[0] == fxpRemove || b[0] == fxpMkdir || b[0] == fxpRmdir || b[0] == fxpRename
		if b[0] == fxpRename {
			target = d.str()
		}
		if b[0] == fxpSetstat || b[0] == fxpMkdir {
			tail = d.b
			e.Attributes = d.attrs()
		}
	case fxpClose, fxpRead, fxpWrite, fxpFstat, fxpFsetstat, fxpReaddir:
		e.Command = map[byte]string{fxpClose: "close", fxpRead: "read", fxpWrite: "write", fxpFstat: "fstat", fxpFsetstat: "fsetstat", fxpReaddir: "readdir"}[b[0]]
		handle = d.str()
		h = p.handles[handle]
		if h == nil {
			return sftpStatus(id, fxFailure, "unknown file handle"), nil
		}
		tail = d.b
		switch b[0] {
		case fxpRead:
			e.Offset, e.Size = d.u64(), d.u32()
			if !h.read || h.directory || e.Size > maxSFTPPacket-9 {
				d.err = true
			}
		case fxpWrite:
			e.Offset = d.u64()
			data := d.str()
			e.Size = uint32(len(data))
			if !h.write || h.directory {
				d.err = true
			}
		case fxpFsetstat:
			e.Attributes = d.attrs()
		case fxpReaddir:
			if !h.directory {
				d.err = true
			}
		}
	default:
		return sftpStatus(id, fxOpUnsupported, "unsupported SFTP operation"), nil
	}
	if d.err || len(d.b) != 0 {
		return sftpStatus(id, fxBadMessage, "malformed SFTP request"), nil
	}
	if (b[0] == fxpOpen || b[0] == fxpOpendir) && len(p.handles) >= 1024 {
		return sftpStatus(id, fxFailure, "too many open handles"), nil
	}
	if h != nil {
		name = h.path
	} else {
		// Check the requested name before resolving it, then the canonical name.
		e.Path = path.Clean("/" + name)
		if target != "" {
			e.Target = path.Clean("/" + target)
		}
		if err := p.check(&e); err != nil {
			return nil, err
		}
		var err error
		name, err = p.resolve(name, entry, create)
		if err != nil {
			return nil, err
		}
		if b[0] == fxpRename {
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
		if err := p.check(&e); err != nil {
			return nil, err
		}
	}
	if b[0] == fxpRealpath {
		r := binary.BigEndian.AppendUint32([]byte{fxpName}, id)
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
	if b[0] == fxpRename {
		request = append(request, sftpString(target)...)
	}
	request = append(request, tail...)
	r, err := p.rpc(request)
	if err != nil {
		return nil, err
	}
	if r[0] == fxpHandle && (b[0] == fxpOpen || b[0] == fxpOpendir) {
		d := sftpDecoder{b: r[5:]}
		remote := d.str()
		if d.err || len(d.b) != 0 {
			return nil, errors.New("invalid handle")
		}
		p.next++
		local := fmt.Sprint(p.next)
		p.handles[local] = &sftpHandle{remote: remote, path: name, read: e.Read, write: e.Write, directory: b[0] == fxpOpendir}
		return append(r[:5], sftpString(local)...), nil
	}
	if r[0] == fxpStatus && len(r) >= 9 && binary.BigEndian.Uint32(r[5:9]) == fxOK {
		if b[0] == fxpClose {
			delete(p.handles, handle)
		}
		if b[0] == fxpRename {
			for _, h := range p.handles {
				if h.path == name || strings.HasPrefix(h.path, name+"/") {
					h.path = target + strings.TrimPrefix(h.path, name)
				}
			}
		}
	}
	return r, nil
}

type SFTPRequest SFTPFacts

func (v *SFTPRequest) Describe() (facts.Facts, error) {
	details := Details{SFTP: (*SFTPFacts)(v)}
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
