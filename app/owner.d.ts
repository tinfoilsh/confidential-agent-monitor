export type Json = null | boolean | number | string | Json[] | { [key: string]: Json }
export type Level = 'off' | 'read' | 'ask' | 'allow'
export type Mode = 'off' | 'ask' | 'allow'
export type Audience = 'me' | 'team' | 'anyone'
export type Trust = 'trusted' | 'untrusted'
export type Decision = 'once' | 'save' | 'deny'
export type RequestState = 'pending' | 'allowed' | 'approved' | 'refused' | 'denied' | 'expired'

export type Access = { level: Level; actions?: Record<string, Mode> }
export type Requirement = { id?: string; message: string }
export type Rule = {
  account: string
  action: string
  operation?: string
  definition?: string
  scope?: Record<string, Json>
  requirements?: Requirement[]
}
export type Identity = {
  key: string
  routes?: boolean
  profile?: boolean
  accounts?: Record<string, Access>
  rules?: Record<string, Rule>
}
export type Account = {
  preset: string
  contents: Audience
  sends: Audience
  strangers?: boolean
  connections?: Record<string, Record<string, { [key: string]: Json }>>
}
export type PresetField = {
  key: string
  label: string
  hint?: string
  secret?: boolean
  multiline?: boolean
  json?: boolean
  list?: boolean
  edit_only?: boolean
  default?: Json
  path?: string[]
  paths?: string[][]
  oauth?: Json
}
export type PresetAction = { title: string; effects?: string[] }
export type Preset = {
  title: string
  group?: string
  defaults?: { contents?: Audience; sends?: Audience; strangers?: boolean }
  fields?: PresetField[]
  connections?: Json
  actions?: Record<string, PresetAction>
  operations?: Record<string, { action: string; effects?: string[] }>
}
export type Label = { audience: Audience; trust: Trust; because?: Record<string, string> }
export type ConnectionStatus = {
  state: string
  error?: string
  details?: { blocked?: number; changes?: string[]; pin?: Json }
}
export type View = {
  generation: number
  host_key: string
  ca: string
  config: {
    identities?: Record<string, Identity> | null
    accounts?: Record<string, Account> | null
    policies?: Record<string, string> | null
    presets?: Record<string, Json> | null
    lattices?: { confidentiality?: boolean; integrity?: boolean }
    allow_networks?: string[] | null
  }
  labels: Record<string, Label>
  status: Record<string, ConnectionStatus>
  fields: Record<string, { path: string[]; kind: string }[]>
  presets: Record<string, Preset>
  vocabulary: Record<string, { change?: boolean; ask?: boolean }>
}
export type RequestDetails = {
  http?: { method: string; host: string; path: string; origin?: string; query?: Record<string, Json>; body_kind?: string }
  graphql?: { kind: string; fields: { name: string }[] }
  mcp?: { tool: string }
  smtp?: { to: string[] }
  mail?: { subject?: string }
  imap?: { command: string; args: string }
  policy?: { source_diff: string; effective_diff: string }
}
export type RequestRecord = {
  id: string
  state: RequestState
  time: string
  expires?: string
  deny?: string[]
  requirements?: Requirement[]
  grant?: { [key: string]: Json }
  definition?: string
  savingDecision?: boolean
  facts: {
    title?: string
    principal: { name: string }
    account: string
    service?: string
    operation?: { id: string; action: string; effects?: string[] }
    parameters?: { [key: string]: Json }
    details?: RequestDetails
  }
}
export type Change = { path: string[]; value?: Json; delete?: boolean }
export type Snapshot = { view: View; requests: RequestRecord[] }
export type PolicyDiff = { source_diff: string; effective_diff: string }
export type BrowserFrame = {
  owner: boolean
  frame?: string
  url?: string
  screenshot?: string
  error?: string
  tabs?: { id: string; title: string; url: string; active: boolean }[]
}
export type PresetFile = { title?: string; catalog?: Json; http?: { operations?: { [key: string]: Json } } & { [key: string]: Json } } & { [key: string]: Json }

export type Request = (method: 'GET' | 'POST', path: string, body?: unknown, signal?: AbortSignal) => Promise<unknown>
export type OwnerApi = {
  read(signal?: AbortSignal): Promise<Snapshot>
  unlock(generation?: number, signal?: AbortSignal): Promise<View>
  edit(changes: Change[], signal?: AbortSignal): Promise<View>
  decide(id: string, decision: Decision, signal?: AbortSignal): Promise<null>
  label(name: string, label: { trust: Trust; audience: Audience }, signal?: AbortSignal): Promise<View>
  preset(name: string, signal?: AbortSignal): Promise<PresetFile>
  policy(effective?: boolean, signal?: AbortSignal): Promise<{ source: string; effective?: string }>
  previewPolicy(source: string, signal?: AbortSignal): Promise<PolicyDiff>
  applyPolicy(source: string, signal?: AbortSignal): Promise<View>
  signIn(account: string, path: string[], redirect: string, credential?: Json, signal?: AbortSignal): Promise<{ url: string }>
  finishSignIn(state: string, code: string, signal?: AbortSignal): Promise<View>
  browser(name: string, body?: { [key: string]: Json | undefined }, signal?: AbortSignal): Promise<BrowserFrame>
  icons(signal?: AbortSignal): Promise<(preset: string) => ConnectorIcon>
}
export type ConnectorIcon = { src: string; dark?: string }
export type IconManifest = { [preset: string]: { src: string; dark?: string } }
export function connectorIcon(manifest: IconManifest | undefined, preset: string, base?: string): ConnectorIcon

export class OwnerError extends Error {
  status: number
  constructor(message: string, status: number)
}
export function ownerClient(options: { endpoint?: string; key: string; generation?: number; fetch?: typeof fetch }): OwnerApi
/** Encode supplied passphrase or legacy owner key for ownerClient's key option. */
export function encodeOwnerKey(input: string): string
export function ownerApi(request: Request, generation?: number, base?: string): OwnerApi

export const LEVELS: { [L in Level]: string }
export const MODES: { [M in Mode]: string }
export const AUDIENCES: { [A in Audience]: string }
export const TRUSTS: { [T in Trust]: string }
export const CATALOG_GROUPS: { [group: string]: string }
export const CREDENTIAL_STATUS: { [kind: string]: string }
export const NEW_PRESET: PresetFile
export const INTEGRATION_PAGES: { start: string; wrapped: string; shell: string; mcp: string }

export function sourceChanges(body: { [key: string]: unknown }, path?: string[]): Change[]
export function applyChanges<T extends object>(target: T, changes: Change[]): T
export function previewChanges(view: View, changes: Change[], shipped?: { [name: string]: PresetFile }): View

export function lattices(view: View): { confidentiality: boolean; integrity: boolean }
export function presetOf(view: View, account: string): Preset
export function connectionName(account: string, key: string): string
export function summary(details?: RequestDetails): string
export function requestTitle(record: RequestRecord): string
export function reasons(record: { requirements?: Requirement[] }): string[]
export function stateAt(record: RequestRecord, now: number): RequestState
export function pendingSoonest(records: RequestRecord[]): RequestRecord[]
export function ordered(records: RequestRecord[], dismissed?: string[]): RequestRecord[]
export function timeLeft(record: RequestRecord, now?: number): string
export function grantText(operation: string | undefined, grant?: { [key: string]: Json }, scope?: { [key: string]: Json }): string
export function saveText(record: RequestRecord): string
export function decisions(record: RequestRecord, now?: number): { once?: boolean; save?: boolean; deny?: boolean; dismiss?: boolean }
export function ruleSentence(rule: Rule): string

export type ActionNode = { key: string; title: string; action: boolean; effects: string[]; total: number; children: ActionNode[] }
export type AccessNode = Omit<ActionNode, 'children'> & { own: Mode | null; inherited: Mode; overrides: number; children: AccessNode[] }
export function actionsOf(view: View, account: string): { [action: string]: PresetAction }
export function effectsOf(view: View, account: string, action: string): string[]
export function mode(access: Access, vocabulary: View['vocabulary'], effects: string[], action: string): Mode
export function actionTree(view: View, account: string): ActionNode[]
export function levelsOf(account?: Account): [Level, string][]
export function agentAccess(view: View, name: string): {
  account: string
  preset: string
  level: Level
  levels: [Level, string][]
  overrides: number
  actions: AccessNode[]
}[]
export function browsingHint(view: View, name: string): boolean
export function labelStatus(view: View, label?: Label): string
export function accountUsers(view: View, account: string): { name: string; level: Level; profile: boolean; overrides: number }[]
export type Review = { key: string; name: string; state?: string; error?: string; blocked: number; added: number; changed: number; removed: number; changes: string[] }
export function reviews(view: View, account: string): Review[]
export function accountStatus(view: View, account: string): { state: 'error' | 'connecting' | 'review' | null; blocked: number }
export function liveConnection(view: View, account: string): string | null

export function fieldPaths(field: PresetField): string[][]
export function setupFields(view: View, preset: string): PresetField[]
export function plainFields(view: View, account: string): (PresetField & { value: Json })[]
export function fieldText(field: PresetField, value?: Json): string
export function readField(field: PresetField, raw: string): Json
export function grantTemplate(view: View, account: string, field: PresetField): Json | undefined
export type CredentialField = PresetField & {
  path: string[]
  kind: string
  status: string
  signIn: boolean
  credential?: { oauth: Json }
}
export function credentialFields(view: View, account: string): CredentialField[]
export function signInLabel(view: View, preset: string): string
export function catalog(view: View): { group: string; title: string; presets: { name: string; title: string; accounts: number }[] }[]

export type ApiSettings = { url: string; auth: 'bearer' | 'header' | 'query'; header: string; prefix: string; query: string }
export function apiSettings(view: View, account?: string): ApiSettings
export function apiSlot(settings: Partial<ApiSettings>, value?: string): { [key: string]: string }
export function apiSetup(view: View, account: string): { placeholder: string; address: string; header?: string; query?: string; value: string } | null

export function draftable(view: View, record: RequestRecord): string | null
export function draftOperation(details: RequestDetails): { id: string } & { [key: string]: Json }
export function withDraft(file: PresetFile, record?: RequestRecord): PresetFile
export function newPreset(name: string): PresetFile
export function presetText(value: unknown): string

export type AccountAnswers = { contents: Audience; strangers: boolean; sends: Audience }
export const edits: {
  pairAgent(name: string, key: string): Change[]
  removeAgent(name: string): Change[]
  replaceKey(name: string, key: string): Change[]
  setRoutes(name: string, routes: boolean): Change[]
  setAccess(name: string, account: string, access: { level?: Level; actions?: { [action: string]: Mode | null } }): Change[]
  copySettings(view: View, from: string, name: string): Change[]
  removeRule(name: string, id: string): Change[]
  setLattice(lattice: 'confidentiality' | 'integrity', on: boolean): Change[]
  setNetworks(text: string): Change[]
  setAccountPolicy(account: string, source: string): Change[]
  approveTools(view: View, account: string, key: string): Change[]
  removeAccount(view: View, account: string): Change[]
  addAccount(view: View, preset: string, form: { name: string; values: { [key: string]: Json }; answers: AccountAnswers; oauth?: string[] }): Change[]
  addCustomApi(view: View, form: { name: string; api: Partial<ApiSettings>; token: string; agent?: string; level?: Level; answers: AccountAnswers }): Change[]
  saveAccount(view: View, account: string, form: {
    answers: AccountAnswers
    api?: Partial<ApiSettings>
    values?: { [key: string]: Json }
    credentials?: { [key: string]: { mode: 'keep' | 'replace' | 'clear'; value?: Json } }
  }): Change[]
  savePreset(name: string, text: string, previous?: PresetFile): Change[]
  removePreset(name: string): Change[]
}
export function integrationGuide(view: View, page: string, href: (route: string[]) => string): string
