unit qnx6;

{$mode ObjFPC}{$H+}
{$O+}

interface

uses
  Classes,
  SysUtils,
  {$IFDEF USEGENERICS}
  Generics.Collections,
  {$ELSE}
  lgHashMap,
  {$ENDIF}
  uMisc,
  qnx6.types,
  qnx6.device,
  qnx6.blockmgr,
  qnx6.inodemgr,
  qnx6.triecache;

  {$include './qnx_consts.inc'}

type
  { TQNX6Fs }
  {$IFDEF USEGENERICS}
  TCachedIDirs = specialize TFastHashMap<dword, TQNX6_ARawDirEntry>;
  {$ELSE}
  TCachedIDirsType = specialize TGLiteHashMapLP<dword, TQNX6_ARawDirEntry, dword>;
  TCachedIDirs = TCachedIDirsType.TMap;
  {$ENDIF}

  TQNX6Fs = class
  private
    fDevice: TQNX6VolumeDevice;
    fBlockMgr: TQNX6BlockManager;
    fInodeMgr: TQNX6InodeManager;

    fCacheInodes: TPathTrieCache;
    fCacheIDirs: TCachedIDirs;

    function GetDirectWrite: boolean;
    procedure SetDirectWrite(AValue: boolean);
    function GetBlockSize: dword;
    function FindOrAddDirEntry(var RDI: TQNX6_ARawDirEntry): integer;
  public
    constructor Create(Stream: TStream);
    destructor Destroy; override;

    function RawDirEntryGetName(var entry: TQNX6_RawDirEntry): utf8string;
    procedure RawDirEntrySetName(var entry: TQNX6_RawDirEntry; NewName: utf8string);

    procedure Open(AllInodes: boolean = False);
    procedure Close;
    procedure Flush;

    // Сервісні функції (делегування в окремі модулі)
    procedure Fsck(var Errors: TStringList; Fix: boolean = False);
    function CompactBlocks: integer;
    function CompactInodes: integer;

    // Створення диска та VFS операції
    procedure CreateImage(blocks, blockSize, inodes: integer);
    function CreateObject(const aName: pchar; mode: word; idx: dword = 0): integer;
    function CreateFile(const aName: pchar; aMode: word): integer;

    function FileExists(const aName: pchar): boolean; overload;
    function FileExists(const aPath: string): boolean; overload;

    function MkDir(const aName: pchar; mode: word): integer;
    function symlink(const aLinksToName, aName: pchar): integer;
    function link(const aLinksToName, aName: pchar): integer;
    function removeFileDir(const aName: pchar; dir: boolean = False): integer;
    function RemoveAll(const aPath: string): integer;
    function RemoveAllIterative(const aPath: string): integer;

    function Rename(const aName, aNewName: pchar): integer;

    // Читання/Запис каталогів та шляхів
    function GetInodeByPath(aName: pchar): dword;
    function NameIdx(Name: utf8string; var RDI: TQNX6_ARawDirEntry): integer;
    function ReadDirectory(idx: dword; var RDI: TQNX6_ARawDirEntry): integer; overload;
    function ReadDirectory(Path: string; var RDI: TQNX6_ARawDirEntry): integer; overload;
    function WriteDirectory(idx: DWord; const RDI: TQNX6_ARawDirEntry): integer;

    // Читання/Запис даних та розмірів
    procedure ReadBlock(idx: dword; buff: Pointer; isize: dword = 0);
    procedure WriteBlock(idx: dword; buff: Pointer; osize: dword = 0);
    function SetSize(idx: dword; newsize: qword): integer;

    // Робота з інодами
    function GetInode(idx: dword): TQNX6_DInode;
    procedure SetInode(idx: dword; const Value: TQNX6_DInode);
    function isValidInode(idx: DWord): boolean; inline;
    procedure EraseInode(idx: dword);

    // Робота з блоками
    function AllocateBlocks(Count: integer; SystemBlock: boolean = False): TDwordArray;
    procedure FreeBlocks(blocks: TDwordArray);

    function GetInodeCount: integer; inline;
    function GetBlockCount: integer; inline;
    function GetFreeInodeCount: integer; inline;
    function GetFreeBlockCount: integer; inline;

    // Властивості
    property Device: TQNX6VolumeDevice read fDevice;
    property BlockMgr: TQNX6BlockManager read fBlockMgr;
    property InodeMgr: TQNX6InodeManager read fInodeMgr;

    property BlockSize: dword read GetBlockSize;
    property Inodes[idx: dword]: TQNX6_DInode read GetInode write SetInode;
    property DirectWrite: boolean read GetDirectWrite write SetDirectWrite;
  end;

function FpS_ISDIR(mode: word): boolean; inline;
function FpS_ISREG(mode: word): boolean; inline;
function POSIXExtractFileName(const APath: string): string;
function POSIXGetParentFolder(const APath: string): string;
procedure POSIXSplitPath(const APath: string; out AParent, AName: string);

implementation

uses
  Math,
  DateUtils,
  qnx6.fsck,
  qnx6.compactor;

function FpS_ISDIR(mode: word): boolean; inline;
begin
  Result := (mode and S_IFMT) = S_IFDIR;
end;

function FpS_ISREG(mode: word): boolean; inline;
begin
  Result := (mode and S_IFMT) = S_IFREG;
end;

// Швидке розбиття шляху за 1 прохід без алокацій
procedure POSIXSplitPath(const APath: string; out AParent, AName: string);
var
  i, len: integer;
begin
  len := Length(APath);
  while (len > 1) and (APath[len] = '/') do Dec(len);

  if len = 0 then
  begin
    AParent := '/';
    AName := '';
    Exit;
  end;

  i := len;
  while (i > 0) and (APath[i] <> '/') do Dec(i);

  if i > 1 then
    AParent := Copy(APath, 1, i - 1)
  else if i = 1 then
    AParent := '/'
  else
    AParent := '/';

  AName := Copy(APath, i + 1, len - i);
end;

function POSIXExtractFileName(const APath: string): string;
var
  dummy: string;
begin
  POSIXSplitPath(APath, dummy, Result);
end;

function POSIXGetParentFolder(const APath: string): string;
var
  dummy: string;
begin
  POSIXSplitPath(APath, Result, dummy);
end;

{ TQNX6Fs }

constructor TQNX6Fs.Create(Stream: TStream);
begin
  inherited Create;
  fDevice := TQNX6VolumeDevice.Create(Stream);
  fBlockMgr := TQNX6BlockManager.Create(fDevice);
  fInodeMgr := TQNX6InodeManager.Create(fDevice, fBlockMgr);

  fCacheInodes := TPathTrieCache.Create;

  {$IFDEF USEGENERICS}
  fCacheIDirs := TCachedIDirs.Create;
  {$ELSE}
  fCacheIDirs.Clear;
  {$ENDIF}
end;

destructor TQNX6Fs.Destroy;
begin
  FreeAndNil(fCacheInodes);

  {$IFDEF USEGENERICS}
  FreeAndNil(fCacheIDirs);
  {$ELSE}
  fCacheIDirs.Clear;
  {$ENDIF}

  FreeAndNil(fInodeMgr);
  FreeAndNil(fBlockMgr);
  FreeAndNil(fDevice);
  inherited Destroy;
end;

function TQNX6Fs.GetDirectWrite: boolean;
begin
  Result := fDevice.DirectWrite;
end;

procedure TQNX6Fs.SetDirectWrite(AValue: boolean);
begin
  fDevice.DirectWrite := AValue;
end;

function TQNX6Fs.GetBlockSize: dword;
begin
  Result := fDevice.BlockSize;
end;

function TQNX6Fs.FindOrAddDirEntry(var RDI: TQNX6_ARawDirEntry): integer;
var
  i: integer;
begin
  for i := 0 to High(RDI) do
  begin
    if (RDI[i].inode = 0) or (RDI[i].inode = $FFFFFFFF) then
      Exit(i);
  end;

  i := Length(RDI);
  SetLength(RDI, i + 1);
  FillChar(RDI[i], SizeOf(TQNX6_RawDirEntry), 0);
  Result := i;
end;

procedure TQNX6Fs.Open(AllInodes: boolean = False);
begin
  fDevice.Open;
  fBlockMgr.LoadBitmap;
  fInodeMgr.LoadInodes(AllInodes);
  fInodeMgr.LoadLongNames;
end;

procedure TQNX6Fs.Close;
begin
  Flush;
  if Assigned(fCacheInodes) then
    fCacheInodes.Clear;
  fCacheIDirs.Clear;
end;

procedure TQNX6Fs.Flush;
begin
  fInodeMgr.Flush;
  fBlockMgr.Flush;
  fDevice.Flush;
end;

procedure TQNX6Fs.Fsck(var Errors: TStringList; Fix: boolean = False);
var
  Checker: TQNX6Fsck;
begin
  Checker := TQNX6Fsck.Create(Self);
  try
    Checker.Execute(Errors, Fix);
  finally
    Checker.Free;
  end;
end;

function TQNX6Fs.CompactBlocks: integer;
var
  Compactor: TQNX6Compactor;
begin
  Compactor := TQNX6Compactor.Create(Self);
  try
    Result := Compactor.CompactBlocks;
  finally
    Compactor.Free;
  end;
end;

function TQNX6Fs.CompactInodes: integer;
var
  Compactor: TQNX6Compactor;
begin
  Compactor := TQNX6Compactor.Create(Self);
  try
    Result := Compactor.CompactInodes;
  finally
    Compactor.Free;
  end;
end;

function TQNX6Fs.GetInode(idx: dword): TQNX6_DInode;
begin
  Result := fInodeMgr.GetInode(idx);
end;

procedure TQNX6Fs.SetInode(idx: dword; const Value: TQNX6_DInode);
begin
  fInodeMgr.SetInode(idx, Value);
end;

function TQNX6Fs.isValidInode(idx: DWord): boolean;
begin
  Result := fInodeMgr.IsValidInode(idx);
end;

procedure TQNX6Fs.EraseInode(idx: dword);
begin
  fInodeMgr.EraseInode(idx);
end;

function TQNX6Fs.AllocateBlocks(Count: integer; SystemBlock: boolean = False): TDwordArray;
begin
  Result := fBlockMgr.AllocateBlocks(Count, SystemBlock);
end;

procedure TQNX6Fs.FreeBlocks(blocks: TDwordArray);
begin
  fBlockMgr.FreeBlocks(blocks);
end;

procedure TQNX6Fs.ReadBlock(idx: dword; buff: Pointer; isize: dword = 0);
begin
  fDevice.ReadBlock(idx, buff, isize);
end;

procedure TQNX6Fs.WriteBlock(idx: dword; buff: Pointer; osize: dword = 0);
begin
  fDevice.WriteBlock(idx, buff, osize);
end;

function TQNX6Fs.RawDirEntryGetName(var entry: TQNX6_RawDirEntry): utf8string;
var
  longEntry: PQNX6_LongNameEntry;
  cryptEntry: PQNX6_CryptNameEntry;
  j: DWord;
begin
  case entry.len of
    QNX6FS_DIR_CRYPTNAME:
    begin
      cryptEntry := PQNX6_CryptNameEntry(@entry.Data[0]);
      j := cryptEntry^.blkno;
      Result := 'encrypted_' + IntToHex(j, 8);
    end;

    QNX6FS_DIR_LONGNAME:
    begin
      longEntry := PQNX6_LongNameEntry(@entry.Data[0]);
      j := longEntry^.blkno;
      if j < DWord(fInodeMgr.LongNames.Count) then
        Result := fInodeMgr.GetLongName(j, longEntry^.cksum)
      else
        Result := 'DAMAGED LONG NAME ENTRY';
    end;

    1..QNX6FS_DIR_SHORT_LEN:
      Result := Copy(PChar(@entry.Data[0]), 1, entry.len);

    else
      Result := 'DAMAGED ENTRY';
  end;
end;

procedure TQNX6Fs.RawDirEntrySetName(var entry: TQNX6_RawDirEntry; NewName: utf8string);
var
  c, j, k: integer;
  chk: DWord;
  tmp: TQNX6_LongName;
  longEntry: PQNX6_LongNameEntry;
  lnamesBlocks: TBlocksList;
  rawSB: TQNX6_SuperBlockRaw;
begin
  c := Length(NewName);
  if c > QNX6FS_NAME_MAX then
    raise Exception.CreateFmt('File name too long (%d > %d)', [c, QNX6FS_NAME_MAX]);

  FillChar(entry.Data[0], SizeOf(entry.Data), 0);

  if (c > QNX6FS_DIR_SHORT_LEN) then
  begin
    k := fInodeMgr.LongNames.IndexOf(NewName);
    if k < 0 then
    begin
      lnamesBlocks := fInodeMgr.LongNameBlocks;
      j := fBlockMgr.AddBlockToChain(lnamesBlocks);
      fInodeMgr.LongNameBlocks := lnamesBlocks;

      k := fInodeMgr.LongNames.Add(NewName);

      if fDevice.DirectWrite then
      begin
        rawSB := fDevice.ActiveSB.RawData;
        rawSB.lnames.indirect := fInodeMgr.LongNameBlocks.top;
        fBlockMgr.SaveBlocks(rawSB.lnames.blocks, lnamesBlocks);
        rawSB.lnames.size := fInodeMgr.LongNameBlocks.level[0].Count * fDevice.BlockSize;
        fDevice.ActiveSB.RawData := rawSB;
      end
      else
        fInodeMgr.ChangedLong := True;
    end;

    longEntry := PQNX6_LongNameEntry(@entry.Data[0]);
    longEntry^.blkno := k;
    entry.len := QNX6FS_DIR_LONGNAME;

    FillChar(tmp.Name[0], SizeOf(tmp.Name), 0);
    tmp.len := c;
    Move(NewName[1], tmp.Name[0], c);

    if (fDevice.ActiveSB.Flags and QNX6FS_LFN_CKSUM) = QNX6FS_LFN_CKSUM then
      chk := qnx6_lfile_checksum(@tmp.Name[0], tmp.len)
    else
      chk := 0;

    longEntry^.cksum := chk;
    fDevice.WriteBlock(fInodeMgr.LongNameBlocks.level[0].Data[k], @tmp, SizeOf(TQNX6_LongName));
    if not fDevice.DirectWrite then
      fInodeMgr.ChangedLong := True;
  end
  else
  begin
    entry.len := c;
    Move(NewName[1], entry.Data[0], c);
  end;
end;

function TQNX6Fs.NameIdx(Name: utf8string; var RDI: TQNX6_ARawDirEntry): integer;
var
  i: integer;
  bName: utf8string;
begin
  Result := -1;
  for i := 0 to High(RDI) do
  begin
    if (RDI[i].inode <> 0) and (RDI[i].inode <> $FFFFFFFF) then
    begin
      bName := RawDirEntryGetName(RDI[i]);
      if bName = Name then
        Exit(i);
    end;
  end;
end;

function TQNX6Fs.GetInodeByPath(aName: pchar): DWord;
var
  pathPart, segment, fullPath: string;
  len, pStart, pEnd, segLen: integer;
  idx, foundInode: DWord;
  DE: TQNX6_ARawDirEntry;
  bName: utf8string;
  i, k, w: integer;
  found: boolean;
  ch, prevCh: char;
begin
  Result := 0;
  if (aName = nil) or (aName^ = #0) then Exit;
  pathPart := string(aName);

  // Нормалізація: згортаємо дубльовані '/'
  w := 0;
  prevCh := #0;
  SetLength(segment, Length(pathPart));
  for i := 1 to Length(pathPart) do
  begin
    ch := pathPart[i];
    if (ch = '/') and (prevCh = '/') then Continue;
    Inc(w);
    segment[w] := ch;
    prevCh := ch;
  end;
  SetLength(segment, w);
  pathPart := segment;
  segment := '';

  len := Length(pathPart);
  while (len > 1) and (pathPart[len] = '/') do Dec(len);
  if (len = 1) and (pathPart[1] = '/') then Exit(1);
  pathPart := Copy(pathPart, 1, len);

  // 1. Пошук у TrieCache найдовшого префіксу
  if fCacheInodes.TryGetLongestPrefix(pathPart, fullPath, foundInode) then
  begin
    if Length(fullPath) = len then
      Exit(foundInode);
    idx := foundInode;
  end
  else
  begin
    idx := 1; // Root inode
    fullPath := '/';
  end;

  // 2. Досканування залишку шляху через ФС
  pStart := Length(fullPath) + 1;
  pEnd := len;

  while pStart <= pEnd do
  begin
    while (pStart <= pEnd) and (pathPart[pStart] = '/') do Inc(pStart);
    if pStart > pEnd then Break;

    i := pStart;
    while (i <= pEnd) and (pathPart[i] <> '/') do Inc(i);
    segLen := i - pStart;
    segment := Copy(pathPart, pStart, segLen);

    found := False;
    k := ReadDirectory(idx, DE);
    if k < 0 then Exit(0);

    for i := 0 to Pred(k) do
    begin
      bName := RawDirEntryGetName(DE[i]);
      if (bName = '.') or (bName = '..') then Continue;

      if SameStr(segment, bName) then
      begin
        if fullPath = '/' then
          fullPath := '/' + bName
        else
          fullPath := fullPath + '/' + bName;

        idx := DE[i].inode;
        fCacheInodes.AddOrSetValue(fullPath, idx);
        found := True;
        Break;
      end;
    end;

    if not found then Exit(0);
    pStart := pStart + segLen;
  end;

  Result := idx;
end;

function TQNX6Fs.ReadDirectory(Path: string; var RDI: TQNX6_ARawDirEntry): integer;
var
  idx: DWord;
begin
  if Path = '' then Exit(-ESysENOENT);

  idx := GetInodeByPath(PChar(Path));
  if idx = 0 then Exit(-ESysENOENT);

  Result := ReadDirectory(idx, RDI);
end;

function TQNX6Fs.ReadDirectory(idx: DWord; var RDI: TQNX6_ARawDirEntry): integer;
var
  Blocks: TBlocksList;
  inode: TQNX6_DInode;
  i, writeIdx, TotalEntries: integer;
  CachedData: TQNX6_ARawDirEntry;
begin
  SetLength(RDI, 0);

  if idx = 0 then Exit(-ESysENOENT);

  if fCacheIDirs.TryGetValue(idx, CachedData) then
  begin
    RDI := Copy(CachedData);
    Exit(Length(RDI));
  end;

  inode := GetInode(idx);
  if not FpS_ISDIR(inode.mode) then Exit(-ESysENOTDIR);
  if inode.size = 0 then Exit(0);

  TotalEntries := inode.size div SizeOf(TQNX6_RawDirEntry);
  SetLength(RDI, TotalEntries);

  fInodeMgr.LoadInodeBlocks(idx, Blocks);
  fBlockMgr.LoadBlockData(Blocks, @RDI[0], inode.size);

  writeIdx := 0;
  for i := 0 to totalEntries - 1 do
  begin
    if (RDI[i].inode <> 0) and (RDI[i].inode <> $FFFFFFFF) then
    begin
      if writeIdx <> i then
        RDI[writeIdx] := RDI[i];
      Inc(writeIdx);
    end;
  end;

  SetLength(RDI, writeIdx);
  Result := writeIdx;

  if Result > 0 then
    fCacheIDirs.AddOrSetValue(idx, Copy(RDI));
end;

function TQNX6Fs.SetSize(idx: DWord; newsize: QWord): integer;
var
  Blocks: TBlocksList;
  oldsize: QWord;
  old_top, old_b, new_b, need, i, j: integer;
  inode: TQNX6_DInode;
  l: array[0..2] of DWord;
  xfreeBlocks, newBlocks: TDwordArray;
  b: DWord;

  procedure insertLevel(level: integer; Count: integer);
  var
    k, currLen: integer;
  begin
    if Count < 1 then Exit;
    newBlocks := AllocateBlocks(Count);
    currLen := Blocks.level[level].Count;
    SetLength(Blocks.level[level].Data, currLen + Count);

    for k := 0 to High(newBlocks) do
      Blocks.level[level].Data[currLen + k] := newBlocks[k];

    Inc(Blocks.level[level].Count, Count);
  end;

begin
  Result := -ESysEFBIG;
  if newsize > fDevice.MaxBlocks * BlockSize then Exit;

  inode := GetInode(idx);
  oldsize := inode.size;
  if oldsize = newsize then Exit(0);

  old_b := iceil(oldsize, BlockSize);
  new_b := iceil(newsize, BlockSize);
  need := new_b - old_b;

  fInodeMgr.LoadInodeBlocks(idx, Blocks);
  old_top := Blocks.top;

  l[0] := new_b;
  if new_b <= QNX6FS_DIRECT_BLKS then
  begin
    Blocks.top := 0;
    l[1] := 0;
    l[2] := 0;
  end
  else if new_b <= QNX6FS_DIRECT_BLKS * fDevice.PtrsInBlock then
  begin
    Blocks.top := 1;
    l[1] := iceil(new_b, fDevice.PtrsInBlock);
    l[2] := 0;
  end
  else
  begin
    Blocks.top := 2;
    l[1] := fDevice.PtrsInBlock * fDevice.PtrsInBlock;
    l[2] := iceil(new_b, fDevice.PtrsInBlock * fDevice.PtrsInBlock);
  end;

  if need > 0 then
  begin
    insertLevel(2, l[2] - Blocks.level[2].Count);
    insertLevel(1, l[1] - Blocks.level[1].Count);
    insertLevel(0, l[0] - Blocks.level[0].Count);
  end
  else
  begin
    SetLength(xfreeBlocks, 0);
    for i := old_top downto 0 do
    begin
      if l[i] < DWord(Blocks.level[i].Count) then
      begin
        for j := l[i] to Pred(Blocks.level[i].Count) do
        begin
          SetLength(xfreeBlocks, Length(xfreeBlocks) + 1);
          xfreeBlocks[High(xfreeBlocks)] := Blocks.level[i].Data[j];
        end;
        Blocks.level[i].Count := l[i];
        SetLength(Blocks.level[i].Data, l[i]);
      end;
    end;
    FreeBlocks(xfreeBlocks);
  end;

  fInodeMgr.SaveInodeBlocks(idx, newsize, Blocks);
  fBlockMgr.IsChanged := True;
  Result := 0;
end;

function TQNX6Fs.WriteDirectory(idx: DWord; const RDI: TQNX6_ARawDirEntry): integer;
var
  Blocks: TBlocksList;
  entrySize, blockCount, totalAllocSize: integer;
  buff: array of byte;
begin
  Result := -1;
  if idx = 0 then Exit;

  entrySize := Length(RDI) * SizeOf(TQNX6_RawDirEntry);
  blockCount := ifThen(entrySize = 0, 0, iceil(entrySize, BlockSize));
  totalAllocSize := blockCount * BlockSize;

  if SetSize(idx, totalAllocSize) < 0 then Exit;

  if blockCount = 0 then
  begin
    fCacheIDirs.Remove(idx);
    fBlockMgr.IsChanged := True;
    Result := 0;
    Exit;
  end;

  SetLength(buff, totalAllocSize);
  FillChar(buff[0], totalAllocSize, 0);

  if entrySize > 0 then
    Move(RDI[0], buff[0], entrySize);

  fCacheIDirs.AddOrSetValue(idx, Copy(RDI));

  fInodeMgr.LoadInodeBlocks(idx, Blocks);
  fBlockMgr.SaveBlockData(Blocks, @buff[0], totalAllocSize);

  fBlockMgr.IsChanged := True;
  Result := 0;
end;

function TQNX6Fs.CreateObject(const aName: pchar; mode: word; idx: DWord = 0): integer;
var
  parentIdx: DWord;
  parentPath, entryName, sName: string;
  entries: TQNX6_ARawDirEntry;
  i: integer;
  inode: TQNX6_DInode;
  NewInode: boolean;
begin
  Result := -ESysENOENT;
  if (aName = nil) or (aName^ = #0) then Exit;
  sName := string(aName);

  POSIXSplitPath(sName, parentPath, entryName);
  if entryName = '' then Exit;

  parentIdx := GetInodeByPath(PChar(parentPath));
  if parentIdx = 0 then Exit;
  if ReadDirectory(parentIdx, entries) < 0 then Exit;
  if NameIdx(entryName, entries) >= 0 then Exit(-ESysEEXIST);

  NewInode := (idx = 0);
  if NewInode then
  begin
    idx := fInodeMgr.CreateInode(mode);
    if idx = 0 then Exit(-ESysENOSPC);
    inode := GetInode(idx);
    inode.nlink := 1;
    SetInode(idx, inode);
  end;

  i := FindOrAddDirEntry(entries);
  RawDirEntrySetName(entries[i], entryName);
  entries[i].inode := idx;
  if WriteDirectory(parentIdx, entries) < 0 then
  begin
    if NewInode then
      EraseInode(idx);
    Exit(-ESysEIO);
  end;

  fCacheIDirs.Remove(parentIdx);
  fCacheInodes.AddOrSetValue(sName, idx);
  Result := idx;
end;

function TQNX6Fs.CreateFile(const aName: pchar; aMode: word): integer;
begin
  Result := CreateObject(aName, aMode or S_IFREG);
  if Result > 0 then Result := 0;
end;

function TQNX6Fs.symlink(const aLinksToName, aName: pchar): integer;
var
  idx: integer;
  blocks: TBlocksList;
  len: integer;
begin
  Result := -ESysENOENT;
  if (aLinksToName = nil) or (aName = nil) then Exit;
  len := StrLen(aLinksToName);
  if len = 0 then Exit;
  idx := CreateObject(aName, $1FF or S_IFLNK);
  if idx <= 0 then Exit(idx);

  SetSize(DWord(idx), len);
  fInodeMgr.LoadInodeBlocks(DWord(idx), blocks);
  fBlockMgr.SaveBlockData(blocks, aLinksToName, len);
  Result := 0;
end;

function TQNX6Fs.link(const aLinksToName, aName: pchar): integer;
var
  targetIdx: DWord;
  inode: TQNX6_DInode;
begin
  Result := -ESysENOENT;
  targetIdx := GetInodeByPath(aLinksToName);
  if targetIdx = 0 then Exit;

  inode := GetInode(targetIdx);
  if FpS_ISDIR(inode.mode) then Exit(-ESysEPERM);

  Result := CreateObject(aName, (inode.mode and $1FF), targetIdx);
  if Result > 0 then
  begin
    Inc(inode.nlink);
    SetInode(targetIdx, inode);
    Result := 0;
  end;
end;

function TQNX6Fs.FileExists(const aName: pchar): boolean;
var
  idx: DWord;
  inode: TQNX6_DInode;
begin
  Result := False;
  if (aName = nil) or (aName^ = #0) then Exit;

  idx := GetInodeByPath(aName);
  if idx = 0 then Exit;

  inode := GetInode(idx);
  // Перевіряємо, чи це звичайний файл (можна адаптувати, якщо потрібні також каталоги)
  Result := FpS_ISREG(inode.mode);
end;

function TQNX6Fs.FileExists(const aPath: string): boolean;
begin
  Result := FileExists(PChar(aPath));
end;

function TQNX6Fs.MkDir(const aName: pchar; mode: word): integer;
var
  idx, parentIdx: DWord;
  parentPath, entryName, sName: string;
  parentEntries, entries: TQNX6_ARawDirEntry;
  inode, parentInode: TQNX6_DInode;
  i: integer;
begin
  Result := -ESysENOENT;
  if (aName = nil) or (aName^ = #0) then Exit;

  sName := string(aName);
  POSIXSplitPath(sName, parentPath, entryName);
  if entryName = '' then Exit;

  parentIdx := GetInodeByPath(PChar(parentPath));
  if parentIdx = 0 then Exit;

  if ReadDirectory(parentIdx, parentEntries) < 0 then Exit;
  if NameIdx(entryName, parentEntries) >= 0 then Exit(-ESysEEXIST);

  idx := fInodeMgr.CreateInode(mode or S_IFDIR);
  if idx = 0 then Exit(-ESysENOSPC);

  SetLength(entries, 2);
  FillChar(entries[0], SizeOf(TQNX6_RawDirEntry) * 2, 0);

  entries[0].inode := idx;
  RawDirEntrySetName(entries[0], '.');

  entries[1].inode := parentIdx;
  RawDirEntrySetName(entries[1], '..');

  if WriteDirectory(idx, entries) < 0 then
  begin
    EraseInode(idx);
    Exit(-ESysEIO);
  end;

  inode := GetInode(idx);
  inode.nlink := 2;
  SetInode(idx, inode);

  i := FindOrAddDirEntry(parentEntries);
  parentEntries[i].inode := idx;
  RawDirEntrySetName(parentEntries[i], entryName);

  if WriteDirectory(parentIdx, parentEntries) < 0 then
  begin
    EraseInode(idx);
    Exit(-ESysEIO);
  end;

  parentInode := GetInode(parentIdx);
  Inc(parentInode.nlink);
  SetInode(parentIdx, parentInode);

  fCacheIDirs.Remove(parentIdx);
  fCacheInodes.AddOrSetValue(sName, idx);

  Result := idx;
end;

function TQNX6Fs.removeFileDir(const aName: pchar; dir: boolean = False): integer;
var
  idx, parentIdx: DWord;
  parentName, entryName, sName: string;
  DE: TQNX6_ARawDirEntry;
  i, j, Count, ValidEntriesCount: integer;
  inode, parentInode: TQNX6_DInode;
  bName: utf8string;
  nowTime: int64;
begin
  Result := -ESysENOENT;

  if (aName = nil) or (aName^ = #0) then
    Exit;

  sName := string(aName);

  { Не дозволяємо видаляти root }
  if (sName = '') or (sName = '/') then
    Exit(-ESysEBUSY);

  { Знаходимо inode об'єкта }
  idx := GetInodeByPath(PChar(sName));
  if idx = 0 then
    Exit;

  inode := GetInode(idx);

  { Перевіряємо тип відповідно до операції }
  if dir then
  begin
    if not FpS_ISDIR(inode.mode) then
      Exit(-ESysENOTDIR);

    { Каталог повинен бути порожнім }
    Count := ReadDirectory(idx, DE);
    if Count < 0 then
      Exit(-ESysEIO);

    ValidEntriesCount := 0;
    for i := 0 to Count - 1 do
    begin
      bName := RawDirEntryGetName(DE[i]);
      if (bName <> '.') and (bName <> '..') then
        Inc(ValidEntriesCount);
    end;

    if ValidEntriesCount <> 0 then
      Exit(-ESysENOTEMPTY);
  end
  else
  begin
    if FpS_ISDIR(inode.mode) then
      Exit(-ESysEISDIR);
  end;

  { Розділяємо parent/name }
  POSIXSplitPath(sName, parentName, entryName);

  if parentName = '' then
    parentName := '/';

  if entryName = '' then
    Exit(-ESysENOENT);

  { Знаходимо parent inode }
  parentIdx := GetInodeByPath(PChar(parentName));
  if parentIdx = 0 then
    Exit;

  parentInode := GetInode(parentIdx);
  if not FpS_ISDIR(parentInode.mode) then
    Exit(-ESysENOTDIR);

  { Читаємо parent directory }
  Count := ReadDirectory(parentIdx, DE);
  if Count < 0 then
    Exit(-ESysEIO);

  { Шукаємо entry }
  i := NameIdx(entryName, DE);
  if i < 0 then
    Exit(-ESysENOENT);

  { Видаляємо entry фізично зі списку }
  for j := i to Count - 2 do
    DE[j] := DE[j + 1];

  SetLength(DE, Count - 1);

  { Спочатку записуємо змінений parent directory }
  if WriteDirectory(parentIdx, DE) <> 0 then
    Exit(-ESysEIO);

  nowTime := DateTimeToUnix(Now);

  { Оновлюємо parent inode }
  parentInode.mtime := nowTime;
  parentInode.ctime := nowTime;

  if dir then
  begin
    { parent втрачає directory link (від .. видаленого каталогу) }
    if parentInode.nlink > 0 then
      Dec(parentInode.nlink);
  end;

  SetInode(parentIdx, parentInode);

  { Зменшуємо link count об'єкта }
  if dir then
    inode.nlink :=
      0  { Каталог знищується повністю (і посилання з parent, і '.') }
  else if inode.nlink > 0 then
    Dec(inode.nlink);

  inode.ctime := nowTime;

  { Якщо link count стал 0 — inode більше не використовується }
  if inode.nlink = 0 then
  begin
    { ВИПРАВЛЕННЯ: Використовуємо SetSize(idx, 0) для коректного звільнення
      всіх рівнів indirect-блоків замість поверхневого FreeBlocks }
    SetSize(idx, 0);

    { Звільняємо inode }
    EraseInode(idx);
  end
  else
    SetInode(idx, inode);

  { Інвалідація кешів }
  fCacheInodes.RemovePrefix(sName);
  fCacheIDirs.Remove(idx);
  fCacheIDirs.Remove(parentIdx);

  Result := 0;
end;

function TQNX6Fs.RemoveAll(const aPath: string): integer;
var
  idx: DWord;
  inode: TQNX6_DInode;
  entries: TQNX6_ARawDirEntry;
  i, res: integer;
  entryName, childPath: string;
begin
  Result := -ESysENOENT;
  if aPath = '' then Exit;

  idx := GetInodeByPath(PChar(aPath));
  if idx = 0 then Exit;

  inode := GetInode(idx);

  if FpS_ISDIR(inode.mode) then
  begin
    res := ReadDirectory(idx, entries);
    if res < 0 then Exit(res);

    for i := 0 to High(entries) do
    begin
      entryName := RawDirEntryGetName(entries[i]);

      if (entryName = '.') or (entryName = '..') then
        Continue;

      if aPath = '/' then
        childPath := '/' + entryName
      else
        childPath := aPath + '/' + entryName;

      res := RemoveAll(childPath);
      if res < 0 then Exit(res);
    end;

    Result := removeFileDir(PChar(aPath), True);
  end
  else
  begin
    Result := removeFileDir(PChar(aPath), False);
  end;
end;

function TQNX6Fs.RemoveAllIterative(const aPath: string): integer;
var
  idx: DWord;
  inode: TQNX6_DInode;
  entries: TQNX6_ARawDirEntry;
  i, res: integer;
  currPath, entryName, childPath: string;

  Stack: array of string;
  DeleteList: array of string;
  IsDirList: array of boolean;

  stackTop: integer;
  itemCount: integer;
begin
  Result := -ESysENOENT;
  if aPath = '' then Exit;

  idx := GetInodeByPath(PChar(aPath));
  if idx = 0 then Exit;

  inode := GetInode(idx);

  if not FpS_ISDIR(inode.mode) then
    Exit(removeFileDir(PChar(aPath), False));

  SetLength(Stack, 16);
  Stack[0] := aPath;
  stackTop := 1;

  itemCount := 0;

  while stackTop > 0 do
  begin
    Dec(stackTop);
    currPath := Stack[stackTop];

    Inc(itemCount);
    if itemCount > Length(DeleteList) then
    begin
      SetLength(DeleteList, itemCount + 64);
      SetLength(IsDirList, itemCount + 64);
    end;
    DeleteList[itemCount - 1] := currPath;
    IsDirList[itemCount - 1] := True;

    idx := GetInodeByPath(PChar(currPath));
    if idx = 0 then Continue;

    res := ReadDirectory(idx, entries);
    if res < 0 then Continue;

    for i := 0 to High(entries) do
    begin
      entryName := RawDirEntryGetName(entries[i]);

      if (entryName = '.') or (entryName = '..') then
        Continue;

      if currPath = '/' then
        childPath := '/' + entryName
      else
        childPath := currPath + '/' + entryName;

      inode := GetInode(entries[i].inode);

      if FpS_ISDIR(inode.mode) then
      begin
        if stackTop >= Length(Stack) then
          SetLength(Stack, Length(Stack) + 16);

        Stack[stackTop] := childPath;
        Inc(stackTop);
      end
      else
      begin
        Inc(itemCount);
        if itemCount > Length(DeleteList) then
        begin
          SetLength(DeleteList, itemCount + 64);
          SetLength(IsDirList, itemCount + 64);
        end;
        DeleteList[itemCount - 1] := childPath;
        IsDirList[itemCount - 1] := False;
      end;
    end;
  end;

  // Видалення об'єктів у зворотній послідовності (від листя до кореня)
  for i := itemCount - 1 downto 0 do
  begin
    res := removeFileDir(PChar(DeleteList[i]), IsDirList[i]);
    if res < 0 then
      Exit(res);
  end;

  Result := 0;
end;

function TQNX6Fs.Rename(const aName, aNewName: pchar): integer;
var
  parentPath1, parentPath2, oldName, newName, sOld, sNew: string;
  parentIdx, oldInodeIdx: DWord;
  entries: TQNX6_ARawDirEntry;
  i: integer;
begin
  Result := -ESysENOENT;
  if (aName = nil) or (aNewName = nil) then Exit;

  sOld := string(aName);
  sNew := string(aNewName);

  POSIXSplitPath(sOld, parentPath1, oldName);
  POSIXSplitPath(sNew, parentPath2, newName);

  if parentPath1 <> parentPath2 then Exit(-ESysEXDEV);

  parentIdx := GetInodeByPath(PChar(parentPath1));
  if parentIdx = 0 then Exit;

  if ReadDirectory(parentIdx, entries) < 0 then Exit(-ESysEIO);
  if NameIdx(newName, entries) >= 0 then Exit(-ESysEEXIST);

  i := NameIdx(oldName, entries);
  if i < 0 then Exit;

  oldInodeIdx := entries[i].inode;

  fCacheInodes.RemovePrefix(sOld);
  RawDirEntrySetName(entries[i], newName);

  if WriteDirectory(parentIdx, entries) < 0 then Exit(-ESysEIO);

  fCacheInodes.AddOrSetValue(sNew, oldInodeIdx);

  fCacheIDirs.Remove(parentIdx);
  fBlockMgr.IsChanged := True;
  Result := 0;
end;

procedure TQNX6Fs.CreateImage(blocks, blockSize, inodes: integer);
var
  i, r1, r2, r3, r4: integer;
  sb: TQNX6_SuperBlock;
  r_inode, b_inode: TQNX6_DInode;
  rootBlock, bootBlock: TDwordArray;
  Data: TBytes;
  rootEntries: array[0..1] of TQNX6_RawDirEntry;
  bootEntries: array[0..1] of TQNX6_RawDirEntry;
  inodesBlks, bitmapBlks: TBlocksList;
  rawSB: TQNX6_SuperBlockRaw;
begin
  if (blockSize mod 512) <> 0 then Exit;
  if inodes * SizeOf(TQNX6_DInode) > blocks * blockSize then Exit;

  fDevice.Stream.Size := 0;
  fDevice.Stream.Position := 0;
  fDevice.BlockSize := blockSize;

  PDword(@bootsect[12])^ := blocks * blockSize;
  fDevice.Stream.WriteBuffer(bootsect[0], SizeOf(bootsect));

  sb := TQNX6_SuperBlock.Create(fDevice.Stream);
  sb.SelfPos := $2000;

  if fDevice.BlockSize <= 4096 then
    fDevice.DataStart := QNX6FS_BOOT_RSRV + QNX6FS_SBLK_RSRV
  else
    fDevice.DataStart := fDevice.BlockSize;

  try
    FillChar(rawSB, SizeOf(TQNX6_SuperBlockRaw), 0);
    fDevice.PtrsInBlock := fDevice.BlockSize div 4;
    fDevice.MaxBlocks := QNX6FS_DIRECT_BLKS * fDevice.PtrsInBlock * fDevice.PtrsInBlock;
    fBlockMgr.Bitmap.Size := blocks;

    r1 := inodes * SizeOf(TQNX6_DInode);
    r2 := iceil(r1, fDevice.BlockSize);
    r3 := iceil(blocks, 8);
    r4 := iceil(r3, fDevice.BlockSize);

    fDevice.Sys0AreaStart := 0;
    fDevice.Sys1AreaStart := (r2 + iceil(r2, fDevice.PtrsInBlock) + r4 + iceil(r4, fDevice.PtrsInBlock));
    fDevice.UserAreaStart := 2 * fDevice.Sys1AreaStart;

    rawSB.Magic := QNX6FS_SIGNATURE2;
    CreateGUID(rawSB.volumeid);
    rawSB.Serial := 1;
    rawSB.version := QNX6FS_FSYS_VERSION;
    rawSB.rsrvblks := QNX6FS_DEFAULT_RSRV;
    rawSB.blocksize := blockSize;
    rawSB.num_inodes := inodes;
    rawSB.free_inodes := inodes - 2;
    rawSB.allocgroup := 16;
    rawSB.num_blocks := blocks;
    rawSB.free_blocks := blocks - fDevice.UserAreaStart;

    rawSB.lnames.size := 0;
    FillChar(rawSB.lnames.blocks, SizeOf(rawSB.lnames.blocks), $FF);

    sb.RawData := rawSB;

    inodesBlks := Default(TBlocksList);
    bitmapBlks := Default(TBlocksList);

    for i := 1 to r2 do fBlockMgr.AddBlockToChain(inodesBlks, True);
    for i := 1 to r4 do fBlockMgr.AddBlockToChain(bitmapBlks, True);

    fInodeMgr.InodesBlocks := inodesBlks;
    fBlockMgr.BitmapBlocks := bitmapBlks;

    r_inode := Default(TQNX6_DInode);
    r_inode.size := fDevice.BlockSize;
    b_inode := Default(TQNX6_DInode);
    b_inode.size := fDevice.BlockSize;

    FillChar(r_inode.blocks, SizeOf(r_inode.blocks), $FF);
    FillChar(b_inode.blocks, SizeOf(b_inode.blocks), $FF);

    rootBlock := AllocateBlocks(1, True);
    bootBlock := AllocateBlocks(1, True);

    r_inode.mode := &777 or S_IFDIR;
    b_inode.mode := &744 or S_IFDIR;
    r_inode.nlink := 3;
    r_inode.blocks[0] := rootBlock[0];
    b_inode.blocks[0] := bootBlock[0];
    b_inode.nlink := 2;

    FillChar(bootEntries, SizeOf(bootEntries), 0);
    bootEntries[0].inode := 2;
    RawDirEntrySetName(bootEntries[0], '.');
    bootEntries[1].inode := 1;
    RawDirEntrySetName(bootEntries[1], '..');

    SetLength(Data, fDevice.BlockSize);
    FillChar(Data[0], fDevice.BlockSize, 0);
    Move(bootEntries[0], Data[0], SizeOf(bootEntries));
    WriteBlock(bootBlock[0], @Data[0]);

    FillChar(rootEntries, SizeOf(rootEntries), 0);
    rootEntries[0].inode := 1;
    RawDirEntrySetName(rootEntries[0], '.');
    rootEntries[1].inode := 2;
    RawDirEntrySetName(rootEntries[1], 'boot');

    FillChar(Data[0], fDevice.BlockSize, 0);
    Move(rootEntries[0], Data[0], SizeOf(rootEntries));
    WriteBlock(rootBlock[0], @Data[0]);

    SetInode(1, r_inode);
    SetInode(2, b_inode);

    rawSB := sb.RawData;
    rawSB.bitmap.size := r3;
    rawSB.bitmap.indirect := bitmapBlks.top;
    fBlockMgr.SaveBlocks(rawSB.bitmap.blocks, bitmapBlks);

    rawSB.inodes.size := r1;
    rawSB.inodes.indirect := inodesBlks.top;
    fBlockMgr.SaveBlocks(rawSB.inodes.blocks, inodesBlks);

    sb.RawData := rawSB;

    Flush;
    sb.Write;
  finally
    FreeAndNil(sb);
  end;
end;

function TQNX6Fs.GetFreeInodeCount: integer;
begin
  if Assigned(fDevice.ActiveSB) then
    Result := fDevice.ActiveSB.FreeInodes
  else
    Result := 0;
end;

function TQNX6Fs.GetFreeBlockCount: integer;
begin
  if Assigned(fDevice.ActiveSB) then
    Result := fDevice.ActiveSB.FreeBlocks
  else
    Result := 0;
end;

function TQNX6Fs.GetInodeCount: integer;
begin
  if Assigned(fDevice.ActiveSB) then
    Result := fDevice.ActiveSB.NumInodes
  else
    Result := 0;
end;

function TQNX6Fs.GetBlockCount: integer;
begin
  if Assigned(fDevice.ActiveSB) then
    Result := fDevice.ActiveSB.NumBlocks
  else
    Result := 0;
end;

end.
