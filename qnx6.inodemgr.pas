unit qnx6.inodemgr;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  Math,
  DateUtils,
  {$IFDEF USEGENERICS}
  Generics.Collections,
  {$ELSE}
  lgHashMap,
  lgList,
  lgUtils,
  {$ENDIF}
  uMisc,
  qnx6.device,
  qnx6.blockmgr,
  qnx6.types;

type
  {$IFDEF USEGENERICS}
  TBlocksChains = specialize TFastHashMap<dword, TBlocksList>;
  TCachedDInodes = specialize TFastHashMap<dword, TQNX6_DInode>;

  TUsedInodes = specialize TSortedList<dword>;
  TChangedList = specialize TSortedList<dword>;
  {$ELSE}
  TBlocksChainsType = specialize TGLiteHashMapLP<dword, TBlocksList, dword>;
  TCachedDInodesType = specialize TGLiteHashMapLP<dword, TQNX6_DInode, dword>;

  TBlocksChains = TBlocksChainsType.TMap;
  TCachedDInodes = TCachedDInodesType.TMap;

  TUsedInodes = specialize TGLiteComparableSortedList<dword>;
  TChangedList = specialize TGLiteComparableSortedList<dword>;
  {$ENDIF}

  { TQNX6InodeManager }

  TQNX6InodeManager = class
  private
    fDevice: TQNX6VolumeDevice;
    fBlockMgr: TQNX6BlockManager;

    fInodesBlocks: TBlocksList;
    fLongNameBlocks: TBlocksList;

    fFirstFreeInode: dword;
    fInodesLoaded: boolean;
    fChangedLong: boolean;

    fLongNames: TStringList;
    fFreeInodes: TFreeBlocks;

    fCacheDInodes: TCachedDInodes;
    fCacheBlocksChains: TBlocksChains;
    fChangedInodes: TChangedList;
    fUsedInodesList: TUsedInodes;

    function InodePos(idx: dword): qword; inline;
    function GetFreeInode: dword;
    procedure ClearCacheChains;
    procedure AddToChangedInodes(idx: dword);
  public
    constructor Create(ADevice: TQNX6VolumeDevice; ABlockMgr: TQNX6BlockManager);
    destructor Destroy; override;

    procedure LoadInodes(all: boolean = False);
    function CreateInode(mode: word): dword;
    procedure EraseInode(idx: dword);
    procedure LoadLongNames;

    function GetInode(idx: dword): TQNX6_DInode;
    procedure SetInode(idx: dword; const Value: TQNX6_DInode);
    function IsValidInode(idx: DWord): boolean; inline;
    function InodeUsed(idx: DWord): boolean;

    procedure PreloadInodes(all: boolean = False);
    procedure LoadInodeBlocks(idx: dword; var xBlocks: TBlocksList);
    procedure SaveInodeBlocks(idx: dword; size: qword; var Blocks: TBlocksList);
    function GetLongName(idx: dword; chk: dword = 0): utf8string;

    procedure Flush;

    property Device: TQNX6VolumeDevice read fDevice;
    property BlockMgr: TQNX6BlockManager read fBlockMgr;
    property InodesBlocks: TBlocksList read fInodesBlocks write fInodesBlocks;
    property LongNameBlocks: TBlocksList read fLongNameBlocks write fLongNameBlocks;
    property LongNames: TStringList read fLongNames;
    property FreeInodes: TFreeBlocks read fFreeInodes;
    property UsedInodesList: TUsedInodes read fUsedInodesList;
    property CacheDInodes: TCachedDInodes read fCacheDInodes;
    property CacheBlocksChains: TBlocksChains read fCacheBlocksChains;
    property ChangedInodes: TChangedList read fChangedInodes;
    property InodesLoaded: boolean read fInodesLoaded write fInodesLoaded;
    property ChangedLong: boolean read fChangedLong write fChangedLong;

    property Inodes[idx: dword]: TQNX6_DInode read GetInode write SetInode; default;
  end;

implementation

{ TQNX6InodeManager }

constructor TQNX6InodeManager.Create(ADevice: TQNX6VolumeDevice;
  ABlockMgr: TQNX6BlockManager);
begin
  inherited Create;
  fDevice := ADevice;
  fBlockMgr := ABlockMgr;

  fInodesLoaded := False;
  fChangedLong := False;
  fFirstFreeInode := 2;

  fFreeInodes := TFreeBlocks.Create;
  fLongNames := TStringList.Create;

  {$IFDEF USEGENERICS}
  fCacheDInodes := TCachedDInodes.Create;
  fCacheBlocksChains := TBlocksChains.Create;

  fChangedInodes := TChangedList.Create;
  fChangedInodes.Duplicates := dupIgnore;
  fChangedInodes.Sorted := True;

  fUsedInodesList := TUsedInodes.Create;
  fUsedInodesList.Duplicates := dupIgnore;
  fUsedInodesList.Sorted := True;
  {$ELSE}
  fCacheDInodes.Clear;
  fCacheBlocksChains.Clear;
  fChangedInodes.Clear;
  fUsedInodesList.Clear;
  {$ENDIF}
end;

procedure TQNX6InodeManager.ClearCacheChains;
begin
  {$IFDEF USEGENERICS}
  if Assigned(fCacheBlocksChains) then
    fCacheBlocksChains.Clear;
  {$ELSE}
  fCacheBlocksChains.Clear;
  {$ENDIF}
end;

destructor TQNX6InodeManager.Destroy;
begin
  ClearCacheChains;

  {$IFDEF USEGENERICS}
  FreeAndNil(fCacheBlocksChains);
  FreeAndNil(fCacheDInodes);
  FreeAndNil(fChangedInodes);
  FreeAndNil(fUsedInodesList);
  {$ELSE}
  fCacheDInodes.Clear;
  fCacheBlocksChains.Clear;
  fChangedInodes.Clear;
  fUsedInodesList.Clear;
  {$ENDIF}

  FreeAndNil(fFreeInodes);
  FreeAndNil(fLongNames);

  inherited Destroy;
end;

function TQNX6InodeManager.InodePos(idx: dword): qword;
var
  q, p, r: QWord;
begin
  q := QWord(idx - 1) * SizeOf(TQNX6_DInode);

  if fDevice.BlockIsPowerOf2 then
  begin
    p := q shr fDevice.BlockShift;
    r := q and fDevice.BlockMask;
  end
  else
  begin
    p := q div fDevice.BlockSize;
    r := q mod fDevice.BlockSize;
  end;

  if (p < DWord(fInodesBlocks.level[0].Count)) then
    Result := fDevice.DataStart + QWord(fInodesBlocks.level[0].Data[p]) *
      fDevice.BlockSize + r
  else
    Result := 0;
end;

procedure TQNX6InodeManager.AddToChangedInodes(idx: dword);
begin
  {$IFDEF USEGENERICS}
  if fChangedInodes.IndexOf(idx) < 0 then
    fChangedInodes.Add(idx);
  {$ELSE}
  fChangedInodes.Add(idx);
  {$ENDIF}
end;

function TQNX6InodeManager.GetFreeInode: dword;
var
  idx, numInodes: dword;
  inode: TQNX6_DInode;
  gotFromQueue: boolean;
begin
  Result := 0;
  if (fDevice = nil) or (fDevice.ActiveSB = nil) then Exit;

  numInodes := fDevice.ActiveSB.NumInodes;

  if fDevice.ActiveSB.FreeInodes = 0 then
    Exit;

  {$IFDEF USEGENERICS}
  gotFromQueue := fFreeInodes.Count > 0;
  if gotFromQueue then
    Result := fFreeInodes.Dequeue;
  {$ELSE}
  gotFromQueue := fFreeInodes.TryDequeue(Result);
  {$ENDIF}

  if gotFromQueue then
  begin
    if fDevice.ActiveSB.FreeInodes > 0 then
      fDevice.ActiveSB.FreeInodes := fDevice.ActiveSB.FreeInodes - 1;
    Exit;
  end;

  idx := fFirstFreeInode;
  while idx <= numInodes do
  begin
    inode := GetInode(idx);
    if inode.mode = 0 then
    begin
      Result := idx;
      fFirstFreeInode := idx + 1;
      if fDevice.ActiveSB.FreeInodes > 0 then
        fDevice.ActiveSB.FreeInodes := fDevice.ActiveSB.FreeInodes - 1;
      Exit;
    end;
    Inc(idx);
  end;
end;

function TQNX6InodeManager.CreateInode(mode: word): dword;
var
  idx: dword;
  inode: TQNX6_DInode;
  t: dword;
begin
  Result := 0;
  idx := GetFreeInode;
  if idx = 0 then
    Exit;

  t := DateTimeToUnix(Now);

  inode := Default(TQNX6_DInode);
  inode.mode := mode;
  inode.nlink := 1;
  inode.flags := 1;

  inode.ftime := t;
  inode.atime := t;
  inode.ctime := t;
  inode.mtime := t;

  FillChar(inode.blocks, SizeOf(inode.blocks), $FF);

  SetInode(idx, inode);
  fBlockMgr.IsChanged := True;

  {$IFDEF USEGENERICS}
  fCacheBlocksChains.AddOrSetValue(idx, Default(TBlocksList));
  {$ELSE}
  fCacheBlocksChains[idx] := Default(TBlocksList);
  {$ENDIF}

  Result := idx;
end;

function TQNX6InodeManager.IsValidInode(idx: DWord): boolean;
begin
  Result := (idx > 0) and (Assigned(fDevice.ActiveSB)) and
    (idx <= fDevice.ActiveSB.NumInodes);
end;

function TQNX6InodeManager.GetInode(idx: dword): TQNX6_DInode;
var
  pos: QWord;
begin
  if not IsValidInode(idx) then
    raise Exception.CreateFmt('Wrong inode number (%d out of range [1..%d])',
      [idx, fDevice.ActiveSB.NumInodes]);

  // Прямий однаковий виклик TryGetValue для обидвох бібліотек
  if fCacheDInodes.TryGetValue(idx, Result) then
    Exit;

  pos := InodePos(idx);
  if pos = 0 then
    raise Exception.CreateFmt('Cannot calculate pos for inode %d', [idx]);

  fDevice.Stream.Seek(pos, fsFromBeginning);
  fDevice.Stream.ReadBuffer(Result, SizeOf(TQNX6_DInode));

  {$IFDEF USEGENERICS}
  fCacheDInodes.AddOrSetValue(idx, Result);
  {$ELSE}
  fCacheDInodes[idx] := Result;
  {$ENDIF}
end;

procedure TQNX6InodeManager.SetInode(idx: dword; const Value: TQNX6_DInode);
var
  pos: QWord;
begin
  if not IsValidInode(idx) then
    raise Exception.CreateFmt('Invalid inode index (%d), max allowed is %d',
      [idx, fDevice.ActiveSB.NumInodes]);

  if fDevice.DirectWrite then
  begin
    pos := InodePos(idx);
    if pos > 0 then
    begin
      fDevice.Stream.Seek(pos, fsFromBeginning);
      fDevice.Stream.WriteBuffer(Value, SizeOf(TQNX6_DInode));
    end;
  end;

  AddToChangedInodes(idx);

  {$IFDEF USEGENERICS}
  fCacheDInodes.AddOrSetValue(idx, Value);
  {$ELSE}
  fCacheDInodes[idx] := Value;
  {$ENDIF}

  fBlockMgr.IsChanged := True;
end;

procedure TQNX6InodeManager.EraseInode(idx: dword);
var
  dinode: TQNX6_DInode;
begin
  if not IsValidInode(idx) then
    Exit;

  dinode := Default(TQNX6_DInode);
  SetInode(idx, dinode);

  fFreeInodes.Enqueue(idx);

  if Assigned(fDevice.ActiveSB) then
    fDevice.ActiveSB.FreeInodes := fDevice.ActiveSB.FreeInodes + 1;

  {$IFDEF USEGENERICS}
  fCacheDInodes.AddOrSetValue(idx, dinode);
  fCacheBlocksChains.Remove(idx);
  fUsedInodesList.Remove(idx);
  {$ELSE}
  fCacheDInodes[idx] := dinode;
  fCacheBlocksChains.Remove(idx);
  fUsedInodesList.Remove(idx);
  {$ENDIF}

  fBlockMgr.IsChanged := True;
end;

function TQNX6InodeManager.InodeUsed(idx: DWord): boolean;
var
  dinode: TQNX6_DInode;
begin
  if not IsValidInode(idx) then
    Exit(False);

  dinode := GetInode(idx);
  Result := dinode.mode <> 0;
end;

procedure TQNX6InodeManager.PreloadInodes(all: boolean = False);
var
  totalCount, freeCount, usedCount: dword;
  preloadCount, countedUsed, currentInode: dword;
  inode: TQNX6_DInode;
  Buff: array of TQNX6_DInode;

  procedure AddInode(index: dword; const AInode: TQNX6_DInode);
  begin
    if AInode.mode = 0 then
    begin
      if fFirstFreeInode = 0 then
        fFirstFreeInode := index;
      fFreeInodes.Enqueue(index);
    end
    else
    begin
      fCacheDInodes.AddOrSetValue(index, AInode);
      fUsedInodesList.Add(index);
      Inc(countedUsed);
    end;
  end;

begin
  if (not Assigned(fDevice.ActiveSB)) or (not fDevice.ActiveSB.isValid) then
    raise Exception.Create('ActiveSB is not set or invalid');

  with fDevice.ActiveSB.RawData do
  begin
    totalCount := num_inodes;
    freeCount := free_inodes;
    usedCount := totalCount - freeCount;
    preloadCount := IfThen(all, totalCount, Min(totalCount, Trunc(usedCount * 1.2)));
  end;

  SetLength(Buff, preloadCount);
  if preloadCount > 0 then
    fBlockMgr.LoadBlockData(fInodesBlocks, @Buff[0], preloadCount *
      SizeOf(TQNX6_DInode));

  fFreeInodes.Clear;
  fUsedInodesList.Clear;
  fCacheDInodes.Clear;

  countedUsed := 0;
  currentInode := 1;
  fFirstFreeInode := 0;

  while (currentInode <= preloadCount) and (all or (countedUsed < usedCount)) do
  begin
    AddInode(currentInode, Buff[currentInode - 1]);
    Inc(currentInode);
  end;

  while (not all) and (countedUsed < usedCount) and (currentInode <= totalCount) do
  begin
    inode := GetInode(currentInode);
    AddInode(currentInode, inode);
    Inc(currentInode);
  end;
  if fFirstFreeInode = 0 then
    fFirstFreeInode := currentInode;

  fInodesLoaded := True;
end;

procedure TQNX6InodeManager.LoadInodes(all: boolean = False);
begin
  with fDevice.ActiveSB.RawData.inodes do
    fBlockMgr.LoadBlocks(blocks, indirect, size, fInodesBlocks);
  fFirstFreeInode := 2;
  PreloadInodes(all);
end;

procedure TQNX6InodeManager.LoadLongNames;
var
  i, c: integer;
begin
  with fDevice.ActiveSB.RawData.lnames do
    fBlockMgr.LoadBlocks(blocks, indirect, size, fLongNameBlocks);

  c := fLongNameBlocks.level[0].Count;
  fLongNames.Sorted := False;
  fLongNames.Clear;
  for i := 0 to Pred(c) do
    fLongNames.Add(GetLongName(i));
  fChangedLong := False;
end;

function TQNX6InodeManager.GetLongName(idx: dword; chk: dword = 0): utf8string;
var
  blockIdx: dword;
  tmp: TQNX6_LongName;
  len: integer;
begin
  if idx >= DWord(fLongNameBlocks.level[0].Count) then
    raise Exception.CreateFmt('GetLongName: invalid index (%d)', [idx]);

  blockIdx := fLongNameBlocks.level[0].Data[idx];
  fDevice.ReadBlock(blockIdx, @tmp, SizeOf(TQNX6_LongName));

  len := Min(integer(tmp.len), SizeOf(tmp.Name));
  SetString(Result, PChar(@tmp.Name[0]), len);
end;

procedure TQNX6InodeManager.LoadInodeBlocks(idx: dword; var xBlocks: TBlocksList);
var
  inode: TQNX6_DInode;
begin
  if idx = 0 then Exit;

  // Прямий однаковий виклик TryGetValue для обидвох бібліотек
  if fCacheBlocksChains.TryGetValue(idx, xBlocks) then
    Exit;

  inode := GetInode(idx);
  fBlockMgr.LoadBlocks(inode.blocks, inode.indirect, inode.size, xBlocks);

  {$IFDEF USEGENERICS}
  fCacheBlocksChains.AddOrSetValue(idx, xBlocks);
  {$ELSE}
  fCacheBlocksChains[idx] := xBlocks;
  {$ENDIF}
end;

procedure TQNX6InodeManager.SaveInodeBlocks(idx: dword; size: qword;
  var Blocks: TBlocksList);
var
  inode: TQNX6_DInode;
begin
  inode := GetInode(idx);

  fBlockMgr.SaveBlocks(inode.blocks, Blocks);

  inode.indirect := Blocks.top;
  inode.size := size;

  SetInode(idx, inode);

  {$IFDEF USEGENERICS}
  fCacheBlocksChains.AddOrSetValue(idx, Blocks);
  {$ELSE}
  fCacheBlocksChains[idx] := Blocks;
  {$ENDIF}

  fBlockMgr.IsChanged := True;
end;

procedure TQNX6InodeManager.Flush;
var
  inode: TQNX6_DInode;
  idx: dword;
  pos: QWord;
  rawSB: TQNX6_SuperBlockRaw;
  {$IFNDEF USEGENERICS}
  i: integer;
  {$ENDIF}
begin
  {$IFDEF USEGENERICS}
  for idx in fChangedInodes do
  begin
    if fCacheDInodes.TryGetValue(idx, inode) then
    begin
      pos := InodePos(idx);
      if pos > 0 then
      begin
        fDevice.Stream.Seek(pos, fsFromBeginning);
        fDevice.Stream.WriteBuffer(inode, SizeOf(TQNX6_DInode));
      end;
    end;
  end;
  {$ELSE}
  for i := 0 to fChangedInodes.Count - 1 do
  begin
    idx := fChangedInodes[i];
    if fCacheDInodes.TryGetValue(idx, inode) then
    begin
      pos := InodePos(idx);
      if pos > 0 then
      begin
        fDevice.Stream.Seek(pos, fsFromBeginning);
        fDevice.Stream.WriteBuffer(inode, SizeOf(TQNX6_DInode));
      end;
    end;
  end;
  {$ENDIF}
  fChangedInodes.Clear;

  fDevice.DirectWrite := True;
  try
    if fChangedLong then
    begin
      rawSB := fDevice.ActiveSB.RawData;
      fBlockMgr.SaveBlocks(rawSB.lnames.blocks, fLongNameBlocks);
      rawSB.lnames.size := fLongNameBlocks.level[0].Count * fDevice.BlockSize;
      fDevice.ActiveSB.RawData := rawSB;
      fChangedLong := False;
    end;
  finally
    fDevice.DirectWrite := False;
  end;
end;

end.
