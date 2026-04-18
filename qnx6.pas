unit qnx6;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  {$IFDEF USEGENERICS}
  Generics.Collections,
  {$ELSE}
  lgVector,
  lgList,
  LGHashMap,
  lgUtils,
  {$ENDIF}
  uMisc,
  bits;

  {$include './qnx_consts.inc'}

type

  TBlocksArray = record
    Count: integer;
    Data: array of dword;
  end;

  TBlocksList = record
    top: integer;
    level: array[0..2] of TBlocksArray;
  end;

  TDwordArray = array of dword;

type
  {$IFDEF USEGENERICS}
  TCachedInodes = specialize TFastHashMap<string, dword>;
  TCachedIDirs = specialize TFastHashMap<dword, TQNX6_ARawDirEntry>;
  TBlocksChains = specialize TFastHashMap<dword, TBlocksList>;
  TCachedDInodes = specialize TFastHashMap<dword, TQNX6_DInode>;
  TChangedBlocks = specialize TFastHashMap<dword, TBytes>;

  TUsedInodes = specialize TSortedList<dword>;
  TChangedList = specialize TSortedList<dword>;

  {$ELSE}
  TCachedInodesType = specialize TGLiteHashMapLP<string, dword, string>;
  TCachedIDirsType = specialize TGLiteHashMapLP<dword, TQNX6_ARawDirEntry, dword>;
  TBlocksChainsType = specialize TGLiteHashMapLP<dword, TBlocksList, dword>;
  TCachedDInodesType = specialize TGLiteHashMapLP<dword, TQNX6_DInode, dword>;
  TChangedBlocksType = specialize TGLiteHashMapLP<dword, TBytes, dword>;

  TCachedInodes = TCachedInodesType.TMap;
  TCachedIDirs = TCachedIDirsType.TMap;
  TBlocksChains = TBlocksChainsType.TMap;
  TCachedDInodes = TCachedDInodesType.TMap;
  TChangedBlocks = TChangedBlocksType.TMap;

  TUsedInodes = specialize TGLiteComparableSortedList<dword>;

  TChangedList = specialize TGLiteComparableSortedList<dword>;
  {$ENDIF}

type
  TQNX6_BootBlock = class
  private
    fMagic: dword;
    foff_qnx6fs: dword;
    fsSubtype: dword;
    fsSize: dword;
    fStream: TStream;
    fValid: boolean;
  public
    procedure Read;
    procedure Write;

    constructor Create(Stream: TStream);

    property isValid: boolean read fValid;
    property Magic: dword read fMagic write fMagic;
    property off_qnx6fs: dword read foff_qnx6fs write foff_qnx6fs;
    property subtype: dword read Fssubtype write Fssubtype;
    property size: dword read fssize write fssize;

  end;

  TQNX6_SuperBlock = class
  private
    fStream: TStream;
    fSelfPos: int64;
    fRawData: TQNX6_SuperBlockRaw;
  public
    constructor Create(Stream: TStream);
    procedure Read;
    procedure Write;
    function isValid: boolean;

    property Magic: dword read fRawData.Magic write fRawData.Magic;
    property CRC: dword read fRawData.CRC write fRawData.CRC;
    property Serial: qword read fRawData.Serial write fRawData.Serial;
    property ctime: dword read fRawData.ctime write fRawData.ctime;
    property atime: dword read fRawData.atime write fRawData.atime;
    property flags: dword read fRawData.flags write fRawData.flags;
    property version: word read fRawData.version write fRawData.version;
    property rsrvblks: word read fRawData.rsrvblks write fRawData.rsrvblks;
    property volumeid: TGuid read fRawData.volumeid write fRawData.volumeid;

    property blocksize: dword read fRawData.blocksize write fRawData.blocksize;
    property num_inodes: dword read fRawData.num_inodes write fRawData.num_inodes;
    property free_inodes: dword read fRawData.free_inodes write fRawData.free_inodes;
    property num_blocks: dword read fRawData.num_blocks write fRawData.num_blocks;
    property free_blocks: dword read fRawData.free_blocks write fRawData.free_blocks;
    property allocgroup: dword read fRawData.allocgroup write fRawData.allocgroup;

    property migrate_blocks: dword read fRawData.migrate_blocks write fRawData.migrate_blocks;
    property scrub_block: dword read fRawData.scrub_block write fRawData.scrub_block;

    property selfPos: int64 read fSelfPos write fSelfPos;

  end;


  TQNX6Fs = class
  private
    fStream: TStream;
    fDirectWrite: boolean;
    fLastPos: dword;

    dataStart: qword;

    fBB: TQNX6_BootBlock;
    fSB0: TQNX6_SuperBlock;
    fSB1: TQNX6_SuperBlock;
    fActiveSB: TQNX6_SuperBlock;

    fdinodes: dword;
    fDirEntries: dword;
    ptrs_in_block: dword;
    fBlockSize: dword;
    fBlockShift: integer;
    fBlockMask: QWord;
    fBlockIsPowerOf2: boolean;
    fMaxBlocks: qword;
    fFirstFreeInode: dword;
    fSys0AreaStart: dword;
    fSys1AreaStart: dword;
    fUserAreaStart: dword;

    fBitmapBlocks: TBlocksList;
    fInodesBlocks: TBlocksList;
    fLongNameBlocks: TBlocksList;

    fIExtraBlocks: TBlocksList;
    fIClaimBlocks: TBlocksList;

    fIExtraRaw: TBytes;
    fIClaimRaw: TBytes;

    fChanged: boolean;
    fChangedLong: boolean;
    fInodesLoaded: boolean;
    UsedInodesList: TUsedInodes;

    fLongNames: TStringList;

    fBitmap: XBits;

    fFreeBlocks: TFreeBlocks;
    fFreeInodes: TFreeBlocks;

    cacheDInodes: TCachedDInodes;
    cacheInodes: TCachedInodes;
    cacheIDirs: TCachedIDirs;

    changedInodes: TChangedList;
    changedBlocks: TChangedBlocks;

    cacheBlocksChains: TBlocksChains;

    function NeededExtraBlocks(r2: integer): integer;
    function inodePos(idx: dword): qword;
    function CreateInode(mode: word): dword;
    function GetFreeInode: dword;
    procedure PreloadInodes(all: boolean = False);
    function GetLongName(idx: dword; chk: dword = 0): utf8string;

    procedure InitBootAndSuperBlock;
    procedure InitBlockSizeAndConstants;
    procedure InitLayoutOffsets;
    procedure LoadBitmap;
    procedure LoadInodes(all: boolean = False);
    procedure LoadLongNames;
    procedure LoadIExtra;
    procedure LoadIClaim;

    function InodeUsed(idx: DWord): boolean;
  public

    constructor Create(Stream: TStream);
    destructor Destroy; override;
    procedure Open(AllInodes: boolean = False);

    procedure Close;
    procedure Flush;

    procedure Fsck(var Errors: TStringList; Fix: boolean = False);

    function CompactBlocks: integer;
    function CompactInodes: integer;

    function CreateObject(const aName: pchar; mode: word; idx: dword = 0): integer;
    function GetInode(idx: dword): TQNX6_DInode;
    procedure SetInode(idx: dword; const Value: TQNX6_DInode);
    function isValidInode(idx: DWord): boolean;

    procedure CreateImage(blocks, blockSize, inodes: integer);

    function RemoveBlockFromChain(var Blocks: TBlocksList; id: dword; idx: integer = -1): TDwordArray;
    function AddBlockToChain(var Blocks: TBlocksList; system: boolean = False): dword;

    procedure LoadBlocks(var xBlocks: TQNX6_DB; level: dword; size: qword; var Blocks: TBlocksList);

    procedure SaveBlocks(var xBlocks: TQNX6_DB; var Blocks: TBlocksList);

    procedure SaveBlockData(var Blocks: TBlocksList; Data: Pointer; size: qword; bs: dword);
    procedure LoadBlockData(var Blocks: TBlocksList; Data: Pointer; size: qword; bs: dword);


    procedure LoadInodeBlocks(idx: dword; var xBlocks: TBlocksList);
    procedure SaveInodeBlocks(idx: dword; size: qword; var Blocks: TBlocksList);

    function GetInodeByPath(aName: pchar): dword;
    function RawDirEntryGetName(var entry: TQNX6_RawDirEntry): utf8string;
    procedure RawDirEntrySetName(var entry: TQNX6_RawDirEntry; NewName: utf8string);

    function NameIdx(Name: utf8string; var RDI: TQNX6_ARawDirEntry): integer;

    function ReadDirectory(idx: dword; var RDI: TQNX6_ARawDirEntry): integer;
    function ReadDirectory(Path: string; var RDI: TQNX6_ARawDirEntry): integer;
    function WriteDirectory(idx: DWord; const RDI: TQNX6_ARawDirEntry): integer;
    function removeFileDir(const aName: pchar; dir: boolean = False): integer;

    function Rename(const aName, aNewName: pchar): integer;

    function CreateFile(const aName: pchar; aMode: word): integer;
    function symlink(const aLinksToName, aName: pchar): integer;
    function link(const aLinksToName, aName: pchar): integer;
    function MkDir(const aName: pchar; mode: word): integer;

    procedure ReadBlock(idx: dword; buff: Pointer; isize: dword = 0);
    procedure WriteBlock(idx: dword; buff: Pointer; osize: dword = 0);
    function SetSize(idx: dword; newsize: qword): integer;

    function AllocateBlocks(Count: integer; System: boolean = False): TDwordArray;

    procedure FreeBlocks(blocks: TDwordArray);
    procedure EraseInode(idx: dword);

    function GetInodeCount: integer; inline;
    function GetBlockCount: integer; inline;

    function GetFreeInodeCount: integer; inline;
    function GetFreeBlockCount: integer; inline;

    property BlockSize: dword read fBlockSize;
    property Inodes[idx: dword]: TQNX6_DInode read GetInode write SetInode;

    property DirectWrite: boolean read fDirectWrite write fDirectWrite;


  end;

implementation

uses
  DateUtils,
  Math,
  CLI.Interfaces,      // Optional: Progress indicators
  CLI.Progress,      // Optional: Progress indicators
  CLI.Console;       // Optional: Colored console output

function FpS_ISDIR(mode: word): boolean; inline;
begin
  Result := S_IFDIR = (mode and S_IFDIR);
end;

function FpS_ISREG(mode: word): boolean; inline;
begin
  Result := S_IFDIR = (mode and S_IFREG);
end;


procedure TQNX6_BootBlock.Write;
begin
  fStream.Position := 0;
  fMagic := QNX_BOOT_MAGIC;
  fStream.WriteDWord(fMagic);

  fStream.WriteDWord(foff_qnx6fs);
  fStream.WriteDWord(fsSubtype);
  fStream.WriteDWord(fsSize);

end;


procedure TQNX6_BootBlock.Read;
begin
  fValid := False;
  fMagic := fStream.ReadDWord;
  if (fMagic and $FFFFFF) = QNX_BOOT_MAGIC then
  begin
    foff_qnx6fs := fStream.ReadDWord();
    fsSubtype := fStream.ReadDWord();
    fsSize := fStream.ReadDWord();

    fValid := True;
  end;

end;

constructor TQNX6_BootBlock.Create(Stream: TStream);
begin
  fStream := Stream;
  fValid := False;
  Self.Read();
end;


constructor TQNX6_SuperBlock.Create(Stream: TStream);
begin
  fStream := Stream;
end;

function TQNX6_SuperBlock.isValid: boolean;
var
  chk: dword;
begin
  chk := CRC32_QNX(@fRawData.Serial, 512 - 8);

  Result := ((fRawData.Magic = QNX6FS_SIGNATURE) or (fRawData.Magic = QNX6FS_SIGNATURE2)) and
    (chk = fRawData.CRC);
end;

procedure TQNX6_SuperBlock.Read;
begin
  fStream.Position := fSelfPos;
  fStream.Read(fRawData, SizeOf(fRawData));
end;

procedure TQNX6_SuperBlock.Write;
begin
  //Inc(fRawData.Serial);
  fRawData.CRC := CRC32_QNX(@fRawData.Serial, 512 - 8);
  fStream.Position := fSelfPos;
  fStream.Write(fRawData, SizeOf(fRawData));
end;


function TQNX6Fs.inodePos(idx: DWord): QWord; inline;
var
  q, p, r: QWord;
begin
  q := (idx - 1) * SizeOf(TQNX6_DInode);

  if fBlockIsPowerOf2 then
  begin
    p := q shr fBlockShift;    // q div fBlockSize
    r := q and fBlockMask;     // q mod fBlockSize
  end
  else
  begin
    p := q div fBlockSize;
    r := q mod fBlockSize;
  end;

  Result := dataStart + QWord(fInodesBlocks.level[0].Data[p]) * fBlockSize + r;
end;

function TQNX6Fs.GetFreeInode: DWord;
var
  idx: DWord;
begin
  Result := 0;

  with fActiveSB do
  begin
    if fRawData.free_inodes = 0 then
      Exit;

    if fFreeInodes.TryDequeue(Result) then
    begin
      Dec(fRawData.free_inodes);
      Exit;
    end;

    idx := fFirstFreeInode;
    while idx < num_inodes do
    begin
      if GetInode(idx).blocks[0] = 0 then
      begin
        Result := idx;
        fFirstFreeInode := idx + 1;
        Dec(fRawData.free_inodes);
        Exit;
      end;
      Inc(idx);
    end;
  end;
end;

function TQNX6Fs.CreateInode(mode: word): DWord;
var
  idx: integer;
  inode: TQNX6_DInode;
  t: DWord;
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

  FillDWord(inode.blocks[0], Length(inode.blocks), $FFFFFFFF);

  SetInode(idx, inode);
  fChanged := True;

  cacheBlocksChains.AddOrSetValue(idx, Default(TBlocksList));

  Result := idx;
end;


function TQNX6Fs.isValidInode(idx: DWord): boolean; inline;
begin
  Result := (idx > 0) and (idx <= fActiveSB.num_inodes);
end;

function TQNX6Fs.GetInode(idx: DWord): TQNX6_DInode;
begin
  if (idx = 0) or (idx > fActiveSB.num_inodes) then
    raise Exception.CreateFmt('Wrong inode number (%d out of range [1..%d])', [idx, fActiveSB.num_inodes]);

  if cacheDInodes.TryGetValue(idx, Result) then
    Exit;

  fStream.Position := inodePos(idx);
  fStream.ReadBuffer(Result, SizeOf(TQNX6_DInode)); // Р‘РµР·РїРµС‡РЅС–С€Рµ, РЅС–Р¶ Read

  cacheDInodes.AddOrSetValue(idx, Result);
end;

procedure TQNX6Fs.SetInode(idx: DWord; const Value: TQNX6_DInode);
var
  existing: TQNX6_DInode;
begin
  if (idx = 0) or (idx > fActiveSB.num_inodes) then
    raise Exception.CreateFmt('Invalid inode index (%d), max allowed is %d', [idx, fActiveSB.num_inodes]);

  if fDirectWrite then
  begin
    fStream.Position := inodePos(idx);
    fStream.WriteBuffer(Value, SizeOf(TQNX6_DInode)); // Р‘РµР·РїРµС‡РЅРёР№ Р·Р°РїРёСЃ
  end
  else
    changedInodes.Add(idx);

  cacheDInodes.AddOrSetValue(idx, Value);
  fChanged := True;
end;


function TQNX6Fs.removeFileDir(const aName: pchar; dir: boolean = False): integer;
var
  idx, parentIdx: DWord;
  parentName, entryName: string;
  DE: TQNX6_ARawDirEntry;
  i, Count: integer;
  inode, pInode: TQNX6_DInode;
  blocks: TBlocksList;
begin
  Result := -ESysENOENT;
  idx := GetInodeByPath(aName);
  if idx = 0 then Exit;

  inode := GetInode(idx);

  // РџРµСЂРµРІС–СЂРєР° РґР»СЏ РґРёСЂРµРєС‚РѕСЂС–Р№
  if dir then
  begin
    if not FpS_ISDIR(inode.mode) then Exit(-ESysENOTDIR);
    Count := ReadDirectory(idx, DE);
    if Count > 2 then Exit(-ESysENOTEMPTY); // РјР°СЋС‚СЊ Р±СѓС‚Рё С‚С–Р»СЊРєРё "." С‚Р° ".."
  end;

  // РџРѕС€СѓРє Сѓ Р±Р°С‚СЊРєС–РІСЃСЊРєС–Р№ РґРёСЂРµРєС‚РѕСЂС–С—
  entryName := ExtractFileName(ExcludeTrailingPathDelimiter(aName));
  parentName := GetParentFolder(aName);
  parentIdx := GetInodeByPath(PChar(parentName));
  if parentIdx = 0 then Exit;

  Count := ReadDirectory(parentIdx, DE);
  i := NameIdx(entryName, DE);
  if i < 0 then Exit;

  // 1. Р’РёРґР°Р»СЏС”РјРѕ Р·Р°РїРёСЃ С–Р· Р±Р°С‚СЊРєС–РІСЃСЊРєРѕС— РґРёСЂРµРєС‚РѕСЂС–С—
  Delete(DE, i, 1);
  WriteDirectory(parentIdx, DE);

  // 2. Р—РјРµРЅС€СѓС”РјРѕ Р»С–С‡РёР»СЊРЅРёРє РїРѕСЃРёР»Р°РЅСЊ РѕСЃРЅРѕРІРЅРѕРіРѕ С–РЅРѕРґР°
  if inode.nlink > 0 then
    Dec(inode.nlink);

  // 3. РЎРїРµС†РёС„С–РєР° РґР»СЏ РґРёСЂРµРєС‚РѕСЂС–Р№ (Р·РјРµРЅС€СѓС”РјРѕ nlink Р±Р°С‚СЊРєР°, Р±Рѕ Р·РЅРёРєР°С” "..")
  if dir then
  begin
    pInode := GetInode(parentIdx);
    if pInode.nlink > 0 then
    begin
      Dec(pInode.nlink);
      SetInode(parentIdx, pInode);
    end;
    // Р”РёСЂРµРєС‚РѕСЂС–СЏ С‚Р°РєРѕР¶ РІС‚СЂР°С‡Р°С” РІР»Р°СЃРЅРµ РїРѕСЃРёР»Р°РЅРЅСЏ "."
    if inode.nlink > 0 then Dec(inode.nlink);
  end;

  // 4. Р¤Р†Р—Р�Р§РќР• Р’Р�Р”РђР›Р•РќРќРЇ: С‚С–Р»СЊРєРё СЏРєС‰Рѕ РїРѕСЃРёР»Р°РЅСЊ Р±С–Р»СЊС€Рµ РЅРµРјР°С”
  if inode.nlink = 0 then
  begin
    LoadInodeBlocks(idx, blocks);
    // Р—РІС–Р»СЊРЅСЏС”РјРѕ РІСЃС– СЂС–РІРЅС– С–РЅРґРµРєСЃР°С†С–С— С‚Р° Р±Р»РѕРєРё РґР°РЅРёС…
    for i := 0 to High(blocks.level) do
      if blocks.level[i].Count > 0 then
        FreeBlocks(blocks.level[i].Data);

    EraseInode(idx);
  end
  else
  begin
    // РЇРєС‰Рѕ РїРѕСЃРёР»Р°РЅРЅСЏ С‰Рµ С”, РїСЂРѕСЃС‚Рѕ РѕРЅРѕРІР»СЋС”РјРѕ С–РЅРѕРґ РЅР° РґРёСЃРєСѓ
    SetInode(idx, inode);
  end;

  cacheInodes.Remove(aName);
  Result := 0;
end;

function TQNX6Fs.CreateFile(const aName: pchar; aMode: word): integer;
begin
  Result := CreateObject(aName, aMode or S_IFREG);
  if Result > 0 then Result := 0;
end;

function TQNX6Fs.symlink(const aLinksToName, aName: pchar): integer;
var
  idx: DWord;
  blocks: TBlocksList;
  inode: TQNX6_DInode;
  len: integer;
begin
  Result := -ESysENOENT;

  if (aLinksToName = nil) or (aName = nil) then
    Exit;

  len := StrLen(aLinksToName);
  if len = 0 then
    Exit;

  // S_IFLNK = С‚РёРї СЃРёРјРІРѕР»СЊРЅРѕРіРѕ РїРѕСЃРёР»Р°РЅРЅСЏ, $1FF = РїСЂР°РІР° РґРѕСЃС‚СѓРїСѓ 0777
  idx := CreateObject(aName, $1FF or S_IFLNK);
  if idx <= 0 then
  begin
    Result := idx; // РїРµСЂРµРґР°С‚Рё РєРѕРґ РїРѕРјРёР»РєРё
    Exit;
  end;

  SetSize(idx, len);
  LoadInodeBlocks(idx, blocks);
  SaveBlockData(blocks, aLinksToName, len, fBlockSize);

  Result := 0;
end;

function TQNX6Fs.link(const aLinksToName, aName: pchar): integer;
var
  targetIdx: DWord;
  inode: TQNX6_DInode;
begin
  Result := -ESysENOENT;

  // 1. Р—РЅР°С…РѕРґРёРјРѕ С–РЅРѕРґ С–СЃРЅСѓСЋС‡РѕРіРѕ С„Р°Р№Р»Сѓ
  targetIdx := GetInodeByPath(aLinksToName);
  if targetIdx = 0 then Exit;

  inode := GetInode(targetIdx);

  // 2. QNX6 Р·Р°Р·РІРёС‡Р°Р№ Р·Р°Р±РѕСЂРѕРЅСЏС” hard links РЅР° РґРёСЂРµРєС‚РѕСЂС–С— (С‰РѕР± СѓРЅРёРєРЅСѓС‚Рё С†РёРєР»С–РІ)
  if FpS_ISDIR(inode.mode) then
  begin
    Result := -ESysEPERM;
    Exit;
  end;

  // 3. РЎС‚РІРѕСЂСЋС”РјРѕ РЅРѕРІРёР№ Р·Р°РїРёСЃ Сѓ РґРёСЂРµРєС‚РѕСЂС–С—, РІРєР°Р·СѓСЋС‡Рё РЅР° СЃС‚Р°СЂРёР№ С–РЅРѕРґ
  // РџРµСЂРµРґР°С”РјРѕ targetIdx СЏРє С‚СЂРµС‚С–Р№ РїР°СЂР°РјРµС‚СЂ Сѓ CreateObject
  Result := CreateObject(aName, (inode.mode and $1FF), targetIdx);

  if Result > 0 then
  begin
    // 4. Р†РЅРєСЂРµРјРµРЅС‚СѓС”РјРѕ Р»С–С‡РёР»СЊРЅРёРє РїРѕСЃРёР»Р°РЅСЊ РІ С–РЅРѕРґС–
    Inc(inode.nlink);
    SetInode(targetIdx, inode);
    Result := 0;
  end;
end;


function TQNX6Fs.MkDir(const aName: pchar; mode: word): integer;
var
  idx, parentIdx: DWord;
  parentPath, entryName: string;
  parentEntries, entries: TQNX6_ARawDirEntry;
  inode, parentInode: TQNX6_DInode;
  i: integer;
begin
  Result := -ESysENOENT;

  if (aName = nil) or (aName^ = #0) then Exit;

  entryName := ExtractFileName(ExcludeTrailingPathDelimiter(aName));
  if entryName = '' then Exit;

  parentPath := GetParentFolder(aName);
  parentIdx := GetInodeByPath(PChar(parentPath));
  if parentIdx = 0 then Exit;

  if ReadDirectory(parentIdx, parentEntries) < 0 then Exit;

  if NameIdx(entryName, parentEntries) >= 0 then
  begin
    Result := -ESysEEXIST;
    Exit;
  end;

  // СЃС‚РІРѕСЂСЋС”РјРѕ С–РЅРѕРґ РґРёСЂРµРєС‚РѕСЂС–С—
  idx := CreateInode(mode or S_IFDIR);
  if idx = 0 then
  begin
    Result := -ESysENOSPC;
    Exit;
  end;

  inode := GetInode(idx);

  // С–РЅС–С†С–Р°Р»С–Р·Р°С†С–СЏ "." С– ".."
  SetLength(entries, 2);
  RawDirEntrySetName(entries[0], '.');

  entries[0].inode := idx;
  RawDirEntrySetName(entries[1], '..');
  entries[1].inode := parentIdx;

  if WriteDirectory(idx, entries) < 0 then
  begin
    EraseInode(idx);
    Result := -ESysEIO;
    Exit;
  end;

  // РІРёСЃС‚Р°РІР»СЏС”РјРѕ nlink = 2 ('.' С– Р·Р°РїРёСЃ Сѓ Р±Р°С‚СЊРєС–РІСЃСЊРєС–Р№ РґРёСЂРµРєС‚РѕСЂС–С—)
  inode.nlink := 2;

  SetInode(idx, inode);

  // РґРѕРґР°С”РјРѕ РЅРѕРІРёР№ Р·Р°РїРёСЃ Сѓ Р±Р°С‚СЊРєС–РІСЃСЊРєСѓ РґРёСЂРµРєС‚РѕСЂС–СЋ
  i := Length(parentEntries);
  SetLength(parentEntries, i + 1);
  RawDirEntrySetName(parentEntries[i], entryName);
  parentEntries[i].inode := idx;
  if WriteDirectory(parentIdx, parentEntries) < 0 then
  begin
    EraseInode(idx);
    Result := -ESysEIO;
    Exit;
  end;

  // Р·Р±С–Р»СЊС€СѓС”РјРѕ nlink Сѓ Р±Р°С‚СЊРєР° (С‡РµСЂРµР· РЅРѕРІРёР№ "..")
  parentInode := GetInode(parentIdx);
  Inc(parentInode.nlink);
  SetInode(parentIdx, parentInode);

  //cacheIDirs.AddOrSetValue(idx, entries);
  Result := idx;
end;


function TQNX6Fs.CreateObject(const aName: pchar; mode: word; idx: DWord = 0): integer;
var
  parentIdx: DWord;
  parentPath, entryName: string;
  entries: TQNX6_ARawDirEntry;
  i: integer;
  inode: TQNX6_DInode;
begin
  Result := -ESysENOENT;

  if (aName = nil) or (aName^ = #0) then Exit;

  entryName := ExtractFileName(ExcludeTrailingPathDelimiter(aName));
  if entryName = '' then Exit;

  parentPath := GetParentFolder(aName);
  parentIdx := GetInodeByPath(PChar(parentPath));
  if parentIdx = 0 then Exit;

  if ReadDirectory(parentIdx, entries) < 0 then Exit;

  if NameIdx(entryName, entries) >= 0 then
  begin
    Result := -ESysEEXIST;
    Exit;
  end;

  // СЃС‚РІРѕСЂСЋС”РјРѕ С–РЅРѕРґ, СЏРєС‰Рѕ РЅРµ РїРµСЂРµРґР°РЅРёР№
  if idx = 0 then
  begin
    idx := CreateInode(mode);
    if idx = 0 then
    begin
      Result := -ESysENOSPC;
      Exit;
    end;
  end;

  inode := GetInode(idx);

  // РґР»СЏ С„Р°Р№Р»С–РІ: nlink = 1 (РѕРґРёРЅ Р·Р°РїРёСЃ Сѓ РґРёСЂРµРєС‚РѕСЂС–С—)
  inode.nlink := 1;
  SetInode(idx, inode);

  // РґРѕРґР°С”РјРѕ Р·Р°РїРёСЃ Сѓ Р±Р°С‚СЊРєС–РІСЃСЊРєСѓ РґРёСЂРµРєС‚РѕСЂС–СЋ
  i := Length(entries);
  SetLength(entries, i + 1);
  RawDirEntrySetName(entries[i], entryName);
  entries[i].inode := idx;

  if WriteDirectory(parentIdx, entries) < 0 then
  begin
    EraseInode(idx); // РїСЂРё РїРѕРјРёР»С†С– Р·РЅРёС‰СѓС”РјРѕ
    Result := -ESysEIO;
    Exit;
  end;

  cacheInodes.AddOrSetValue(aName, idx);
  Result := idx;
end;

function TQNX6Fs.Rename(const aName, aNewName: pchar): integer;
var
  parentPath1, parentPath2, oldName, newName: string;
  parentIdx: DWord;
  entries: TQNX6_ARawDirEntry;
  i, c: integer;
begin
  Result := -ESysENOENT;

  oldName := ExtractFileName(ExcludeTrailingPathDelimiter(aName));
  newName := ExtractFileName(ExcludeTrailingPathDelimiter(aNewName));
  parentPath1 := GetParentFolder(aName);
  parentPath2 := GetParentFolder(aNewName);

  // РџРµСЂРµС–РјРµРЅСѓРІР°РЅРЅСЏ С‚С–Р»СЊРєРё РІ РјРµР¶Р°С… РѕРґРЅС–С”С— РґРёСЂРµРєС‚РѕСЂС–С—
  if parentPath1 <> parentPath2 then
  begin
    Result := -ESysEXDEV; // Cross-device link
    Exit;
  end;

  parentIdx := GetInodeByPath(PChar(parentPath1));
  if parentIdx = 0 then
    Exit;

  if ReadDirectory(parentIdx, entries) < 0 then
  begin
    Result := -ESysEIO;
    Exit;
  end;

  // РџРµСЂРµРІС–СЂРєР°: С‡Рё РІР¶Рµ С–СЃРЅСѓС” С„Р°Р№Р» С–Р· РЅРѕРІРёРј С–РјРµРЅРµРј
  if NameIdx(newName, entries) >= 0 then
  begin
    Result := -ESysEEXIST;
    Exit;
  end;

  // Р—РЅР°С…РѕРґРёРјРѕ СЃС‚Р°СЂСѓ РЅР°Р·РІСѓ
  i := NameIdx(oldName, entries);
  if i < 0 then
    Exit;

  // РџРµСЂРµР№РјРµРЅСѓРІР°РЅРЅСЏ
  cacheInodes.Remove(aName);
  RawDirEntrySetName(entries[i], newName);

  if WriteDirectory(parentIdx, entries) < 0 then
  begin
    Result := -ESysEIO;
    Exit;
  end;

  fChanged := True;
  Result := 0;
end;

function TQNX6Fs.SetSize(idx: DWord; newsize: QWord): integer;
var
  Blocks: TBlocksList;
  oldsize: QWord;
  old_b, new_b, need, i, j: integer;
  inode: TQNX6_DInode;
  l: array[0..2] of DWord;
  xfreeBlocks, newBlocks: TDwordArray;
  b: DWord;

  procedure insertLevel(level: integer; Count: integer);
  var
    k: integer;
  begin
    if Count < 1 then Exit;
    newBlocks := AllocateBlocks(Count);
    for k := 0 to High(newBlocks) do
    begin
      b := newBlocks[k];
      Insert(b, Blocks.level[level].Data, Blocks.level[level].Count);
      Inc(Blocks.level[level].Count);
    end;
  end;

begin
  Result := -ESysEFBIG;

  if newsize > fMaxBlocks * fBlockSize then Exit;

  inode := GetInode(idx);
  oldsize := inode.size;
  if oldsize = newsize then Exit(0);

  old_b := iceil(oldsize, fBlockSize);
  new_b := iceil(newsize, fBlockSize);
  need := new_b - old_b;

  LoadInodeBlocks(idx, Blocks);

  // рџ”ў РћР±С‡РёСЃР»РµРЅРЅСЏ РєС–Р»СЊРєРѕСЃС‚С– Р±Р»РѕРєС–РІ РЅР° СЂС–РІРЅСЏС…
  l[0] := new_b;
  if new_b <= QNX6FS_DIRECT_BLKS then
  begin
    Blocks.top := 0;
    l[1] := 0;
    l[2] := 0;
  end
  else if new_b <= QNX6FS_DIRECT_BLKS * ptrs_in_block then
  begin
    Blocks.top := 1;
    l[1] := iceil(new_b, ptrs_in_block);
    l[2] := 0;
  end
  else
  begin
    Blocks.top := 2;
    l[1] := ptrs_in_block * ptrs_in_block;
    l[2] := iceil(new_b, ptrs_in_block * ptrs_in_block);
  end;

  if need > 0 then
  begin
    if (need + NeededExtraBlocks(need)) > fActiveSB.free_blocks then
    begin
      Result := -ESysENOSPC;
      Exit;
    end;

    insertLevel(2, l[2] - Blocks.level[2].Count);
    insertLevel(1, l[1] - Blocks.level[1].Count);
    insertLevel(0, l[0] - Blocks.level[0].Count);
  end
  else
  begin
    SetLength(xfreeBlocks, 0);
    for i := Blocks.top downto 0 do
    begin
      for j := l[i] to Pred(Blocks.level[i].Count) do
        Insert(Blocks.level[i].Data[j], xfreeBlocks, 0);
      Blocks.level[i].Count := l[i];
      SetLength(Blocks.level[i].Data, l[i]);
    end;
    FreeBlocks(xfreeBlocks);
  end;

  SaveInodeBlocks(idx, newsize, Blocks);
  fChanged := True;
  Result := 0;
end;


procedure TQNX6Fs.SaveInodeBlocks(idx: DWord; size: QWord; var Blocks: TBlocksList);
var
  inode: TQNX6_DInode;
begin
  inode := GetInode(idx);

  // Р—Р±РµСЂРµР¶РµРЅРЅСЏ СЃС‚СЂСѓРєС‚СѓСЂРё Р±Р»РѕРєС–РІ Сѓ РјР°СЃРёРІ inode.blocks
  SaveBlocks(inode.blocks, Blocks);

  // РћРЅРѕРІР»РµРЅРЅСЏ СЂС–РІРЅСЏ С–РЅРґРµРєСЃР°С†С–С— С‚Р° СЂРѕР·РјС–СЂСѓ
  inode.indirect := Blocks.top;
  inode.size := size;

  // Р—Р°РїРёСЃ РЅР°Р·Р°Рґ
  SetInode(idx, inode);

  // РћРЅРѕРІР»РµРЅРЅСЏ РєРµС€Сѓ Р±Р»РѕРєС–РІ
  cacheBlocksChains.AddOrSetValue(idx, Blocks);

  fChanged := True;
end;


procedure TQNX6Fs.SaveBlocks(var xBlocks: TQNX6_DB; var Blocks: TBlocksList);
var
  level, toCopy, srcPos, remaining: integer;
  buff: TBytes;
  blockAddr: DWord;
  srcData: PDWord;
begin
  // Р—Р°РїРѕРІРЅРµРЅРЅСЏ РЅСѓР»СЏРјРё Р°Р±Рѕ 0xFF РґР»СЏ РѕС‡РёСЃС‚РєРё РІРёС…С–РґРЅРѕРіРѕ РјР°СЃРёРІСѓ
  FillByte(xBlocks[0], SizeOf(TQNX6_DB), $FF);

  // Р—Р°РїРёСЃ РїСЂСЏРјРѕРіРѕ СЂС–РІРЅСЏ (РЅСѓР»СЊРѕРІРёР№ Р°Р±Рѕ РІРµСЂС…РЅС–Р№ СЂС–РІРµРЅСЊ)
  with Blocks.level[Blocks.top] do
    if Count > 0 then
      Move(Data[0], xBlocks[0], Count * SizeOf(DWord));

  level := Blocks.top;

  if level > 0 then
  begin
    SetLength(buff, fBlockSize);
    srcData := nil;

    // РџСЂРѕС…РѕРґРёРјРѕ Р· РІРµСЂС…РЅСЊРѕРіРѕ СЂС–РІРЅСЏ РІРЅРёР·
    while level > 0 do
    begin
      srcPos := 0;
      remaining := Blocks.level[level - 1].Count;

      for blockAddr in Blocks.level[level].Data do
      begin
        if srcPos >= remaining then
          Break;

        toCopy := Min(ptrs_in_block, remaining - srcPos);
        if toCopy <= 0 then
          Break;

        FillByte(buff[0], fBlockSize, $FF);

        // РљРѕРїС–СЋРІР°РЅРЅСЏ Р±Р»РѕРєСѓ
        srcData := @Blocks.level[level - 1].Data[srcPos];
        Move(srcData^, buff[0], toCopy * SizeOf(DWord));

        WriteBlock(blockAddr, @buff[0]);

        Inc(srcPos, toCopy);
      end;

      Dec(level);
    end;
  end;
end;

procedure TQNX6Fs.LoadBlocks(var xBlocks: TQNX6_DB; level: DWord; size: QWord; var Blocks: TBlocksList);

  procedure GetIBlock(block, level: integer);
  var
    w: DWord;
    buff: TDwordArray;
  begin
    if (level < 0) or (block = $FFFFFFFF) then Exit;

    SetLength(buff, ptrs_in_block);
    ReadBlock(block, @buff[0]);

    with Blocks.level[level] do
      for w in buff do
      begin
        if (w = $FFFFFFFF) or (Count >= Length(Data)) then
          Break;

        if level > 0 then
          GetIBlock(w, level - 1);

        Data[Count] := w;
        Inc(Count);
      end;
  end;

var
  i: integer;
  new_b: DWord;
  l: array[0..2] of DWord;
begin
  new_b := iceil(size, fBlockSize);
  l[0] := new_b;
  l[1] := iceil(new_b, ptrs_in_block);
  l[2] := iceil(new_b, ptrs_in_block * ptrs_in_block);

  Blocks.top := level;

  for i := 0 to 2 do
  begin
    Blocks.level[i].Count := 0;
    SetLength(Blocks.level[i].Data, l[i]);
  end;

  if new_b = 0 then Exit;

  for i := 0 to High(xBlocks) do
  begin
    if (xBlocks[i] = $FFFFFFFF) or (i >= Length(Blocks.level[level].Data)) then
      Break;

    Blocks.level[level].Data[i] := xBlocks[i];
    Inc(Blocks.level[level].Count);

    if level > 0 then
      GetIBlock(xBlocks[i], level - 1);
  end;
end;

procedure TQNX6Fs.LoadInodeBlocks(idx: DWord; var xBlocks: TBlocksList);
var
  inode: TQNX6_DInode;
begin
  if idx = 0 then Exit;

  if cacheBlocksChains.TryGetValue(idx, xBlocks) then
    Exit;

  inode := GetInode(idx);
  LoadBlocks(inode.blocks, inode.indirect, inode.size, xBlocks);
  cacheBlocksChains.AddOrSetValue(idx, xBlocks);
end;


procedure TQNX6Fs.SaveBlockData(var Blocks: TBlocksList; Data: Pointer; size: QWord; bs: DWord);
var
  idx: DWord;
  p, s: QWord;
  src: pbyte;
begin
  if (Data = nil) or (size = 0) or (Length(Blocks.level[0].Data) = 0) then
    Exit;

  p := 0;
  src := pbyte(Data);

  for idx in Blocks.level[0].Data do
  begin
    if p >= size then
      Break;

    s := Min(bs, size - p);
    WriteBlock(idx, @src[p], s);
    Inc(p, s);
  end;
end;

procedure TQNX6Fs.LoadBlockData(var Blocks: TBlocksList; Data: Pointer; size: QWord; bs: DWord);
var
  idx: DWord;
  p, s: QWord;
begin
  if (Data = nil) or (size = 0) or (Length(Blocks.level[0].Data) = 0) then
    Exit;

  p := 0;

  for idx in Blocks.level[0].Data do
  begin
    if p >= size then
      Break;

    s := Min(bs, size - p);

    try
      ReadBlock(idx, pbyte(Data) + p, s);
    except
      on E: Exception do
      begin
        TConsole.WriteLn('ReadBlock failed for block ' + IntToStr(idx) + ': ' + E.Message);
        Exit;
      end;
    end;

    Inc(p, s);
  end;
end;


function TQNX6Fs.NeededExtraBlocks(r2: integer): integer; inline;
var
  level1, level2: integer;
begin
  Result := 0;
  // РЇРєС‰Рѕ Р±Р»РѕРєС–РІ <= 16, РІРѕРЅРё РІСЃС– РІР»С–Р·СѓС‚СЊ РІ С–РЅРѕРґСѓ (Level 0), РґРѕРґР°С‚РєРѕРІС– Р±Р»РѕРєРё РЅРµ РїРѕС‚СЂС–Р±РЅС–
  if r2 <= 16 then Exit(0);

  // РЇРєС‰Рѕ РјРё С‚СѓС‚, Р·РЅР°С‡РёС‚СЊ РЅР°Рј РїРѕС‚СЂС–Р±РµРЅ СЏРє РјС–РЅС–РјСѓРј Level 1.
  // РљРѕР¶РµРЅ Р±Р»РѕРє РґР°РЅРёС… РїРѕС‚СЂРµР±СѓС” Р·Р°РїРёСЃСѓ СЃРІРѕРіРѕ РїРѕРєР°Р¶С‡РёРєР° РІ СЏРєРёР№СЃСЊ С–РЅРґРµРєСЃРЅРёР№ Р±Р»РѕРє.
  level1 := iceil(r2, ptrs_in_block);
  Result := level1;

  // РЇРєС‰Рѕ СЂС–РІРµРЅСЊ 1 РЅРµ РІРјС–С‰Р°С”С‚СЊСЃСЏ Сѓ 16 РїРѕРєР°Р¶С‡РёРєС–РІ С–РЅРѕРґРё
  // (С‚РѕР±С‚Рѕ РєС–Р»СЊРєС–СЃС‚СЊ С–РЅРґРµРєСЃРЅРёС… Р±Р»РѕРєС–РІ > 16)
  if level1 > 16 then
  begin
    level2 := iceil(level1, ptrs_in_block);
    Result := Result + level2;
  end;

  // Р”Р»СЏ QNX6 С‚РµРѕСЂРµС‚РёС‡РЅРѕ С” С– Level 3, Р°Р»Рµ РІ СЂРµР°Р»СЊРЅРёС… РѕР±СЂР°Р·Р°С…
  // (РѕСЃРѕР±Р»РёРІРѕ BlackBerry) РІС–РЅ РјР°Р№Р¶Рµ РЅРµ Р·СѓСЃС‚СЂС–С‡Р°С”С‚СЊСЃСЏ.
end;

procedure TQNX6Fs.PreloadInodes(all: boolean = False);
var
  totalCount, freeCount, usedCount: DWord;
  preloadCount, countedUsed, currentInode: DWord;
  inode: TQNX6_DInode;
  Buff: array of TQNX6_DInode;

  procedure AddInode(index: DWord; const inode: TQNX6_DInode);
  begin
    if inode.acl_iextra_plus_one <> 0 then
      WriteLn('HaveExtra: ',index);

    if inode.blocks[0] = 0 then
      fFreeInodes.Enqueue(index)
    else
    begin
      cacheDInodes.AddOrSetValue(index, inode);
      UsedInodesList.Add(index);
      Inc(countedUsed);
    end;
  end;

begin
  // рџ”ђ РџРµСЂРµРІС–СЂРєР° СЃСѓРїРµСЂР±Р»РѕРєСѓ
  if (not Assigned(fActiveSB)) or (not fActiveSB.isValid) then
    raise Exception.Create('fActiveSB is not set or invalid');

  // рџ“Љ РћС‚СЂРёРјР°С‚Рё РїР°СЂР°РјРµС‚СЂРё С„Р°Р№Р»РѕРІРѕС— СЃРёСЃС‚РµРјРё
  with fActiveSB.fRawData do
  begin
    totalCount := num_inodes;
    freeCount := free_inodes;
    usedCount := totalCount - freeCount;
    preloadCount := IfThen(all, totalCount, Min(totalCount, Trunc(usedCount * 1.2)));
  end;

  // рџ“Ґ Р—Р°РІР°РЅС‚Р°Р¶РµРЅРЅСЏ Р±СѓС„РµСЂР° С–РЅРѕРґС–РІ
  SetLength(Buff, preloadCount);
  LoadBlockData(fInodesBlocks, @Buff[0], preloadCount * SizeOf(TQNX6_DInode), fBlockSize);

  // в™»пёЏ РЎРєРёРґР°РЅРЅСЏ СЃС‚Р°РЅСѓ
  fFreeInodes.Clear;
  UsedInodesList.Clear;
  cacheDInodes.Clear;

  countedUsed := 0;
  currentInode := 1;

  // рџ”„ РџРѕРїРµСЂРµРґРЅС” РєРµС€СѓРІР°РЅРЅСЏ
  while (currentInode <= preloadCount) and ((all) or (countedUsed < usedCount)) do
  begin
    AddInode(currentInode, Buff[currentInode - 1]);
    Inc(currentInode);
  end;

  // рџ§І Р”РѕРІР°РЅС‚Р°Р¶РµРЅРЅСЏ РїСЂРё need
  while (not all) and (countedUsed < usedCount) and (currentInode <= totalCount) do
  begin
    inode := GetInode(currentInode);
    AddInode(currentInode, inode);
    Inc(currentInode);
  end;

  // рџ“Ќ РџС–СЃР»СЏ РѕСЃС‚Р°РЅРЅСЊРѕРіРѕ РІРёРєРѕСЂРёСЃС‚Р°РЅРѕРіРѕ вЂ” РїРµСЂС€РёР№ РІС–Р»СЊРЅРёР№
  fFirstFreeInode := currentInode;
  fInodesLoaded := True;
end;


procedure TQNX6Fs.Open(AllInodes: boolean = False);
begin
  InitBootAndSuperBlock;
  InitBlockSizeAndConstants;
  InitLayoutOffsets;
  //LoadIExtra;
  //LoadIClaim;
  LoadBitmap;
  LoadInodes(AllInodes);
  LoadLongNames;
end;

procedure TQNX6Fs.InitBootAndSuperBlock;
var
  base, o: int64;
  magic, r1: DWord;
begin
  base := fStream.Position;
  magic := fStream.ReadDWord;
  fStream.Position := base;

  if magic = QNX_BOOT_MAGIC then
    fBB := TQNX6_BootBlock.Create(fStream);

  o := 0;
  fSB0 := TQNX6_SuperBlock.Create(fStream);

  while o < $10000 do
  begin
    fStream.Position := base + o;
    r1 := fStream.ReadDWord;
    if (r1 = QNX6FS_SIGNATURE) or (r1 = QNX6FS_SIGNATURE2) then
    begin
      TQNX6_SuperBlock(fSB0).SelfPos := base + o;
      TQNX6_SuperBlock(fSB0).Read;
      if TQNX6_SuperBlock(fSB0).isValid then
      begin
        fActiveSB := fSB0;
        Break;
      end;
    end;
    Inc(o, $100);
  end;

  if Assigned(fBB) and (TQNX6_BootBlock(fBB).fsSubtype = 8) then
  begin
    fSB1 := TQNX6_SuperBlock.Create(fStream);
    fSB1.SelfPos := fStream.Size - fBlockSize;
    fSB1.Read;
    if fSB1.isValid and (fSB1.Serial > fSB0.Serial) then
      fActiveSB := fSB1;
  end;
  if fActiveSB = nil then
    raise Exception.Create('Can''t find superblock. Wrong image file?');
end;

procedure TQNX6Fs.InitBlockSizeAndConstants;
begin
  fBlockSize := fActiveSB.blocksize;
  fdinodes := fBlockSize div SizeOf(TQNX6_DInode);
  fDirEntries := fBlockSize div SizeOf(TQNX6_RawDirEntry);
  ptrs_in_block := fBlockSize div 4;
  fMaxBlocks := QNX6FS_DIRECT_BLKS * ptrs_in_block * ptrs_in_block;

  fBlockIsPowerOf2 := (fBlockSize and (fBlockSize - 1)) = 0;

  if fBlockIsPowerOf2 then
  begin
    fBlockShift := BsrQWord(fBlockSize);  // log2(fBlockSize)
    fBlockMask := fBlockSize - 1;
  end
  else
  begin
    fBlockShift := -1;
    fBlockMask := 0;
  end;
end;

procedure TQNX6Fs.InitLayoutOffsets;
var
  rInodes, rBitmapBytes, rBitmapBlocks: DWord;
begin
  with fActiveSB.fRawData do
  begin
    rInodes := iceil(num_inodes * SizeOf(TQNX6_DInode), fBlockSize);
    rBitmapBytes := iceil(num_blocks, 8);
    rBitmapBlocks := iceil(rBitmapBytes, fBlockSize);

    fSys0AreaStart := 0;
    fSys1AreaStart := rInodes + NeededExtraBlocks(rInodes) + rBitmapBlocks +
      NeededExtraBlocks(rBitmapBlocks);
    fUserAreaStart := 2 * fSys1AreaStart;

    if fBlockSize <= 4096 then
      dataStart := QNX6FS_BOOT_RSRV + QNX6FS_SBLK_RSRV
    else
      dataStart := QNX6FS_BOOT_RSRV + QNX6FS_SBLK_RSRV + abs(
        QNX6FS_BOOT_RSRV + QNX6FS_SBLK_RSRV - fBlockSize);
  end;
end;

procedure TQNX6Fs.LoadBitmap;
begin
  with fActiveSB.fRawData do
  begin
    fBitmap.Size := num_blocks;
    LoadBlocks(bitmap.blocks, bitmap.indirect, bitmap.size, fBitmapBlocks);
    LoadBlockData(fBitmapBlocks, fBitmap.BitsPtr, bitmap.size, fBlockSize);
  end;
end;

procedure TQNX6Fs.LoadInodes(all: boolean = False);
begin
  with fActiveSB.fRawData.inodes do
    LoadBlocks(blocks, indirect, size, fInodesBlocks);
  fFirstFreeInode := 2;
  PreloadInodes(all);
end;


procedure TQNX6Fs.LoadLongNames;
var
  i, c: integer;
begin
  with fActiveSB.fRawData.lnames do
    LoadBlocks(blocks, indirect, size, fLongNameBlocks);

  c := fLongNameBlocks.level[0].Count;
  fLongNames.Sorted := False;
  fLongNames.Clear;
  for i := 0 to Pred(c) do
    fLongNames.Add(GetLongName(i));
  fChangedLong := False;
end;

procedure TQNX6Fs.LoadIExtra;
var
  i, c: integer;
  FileStream: TFileStream;
begin
  with fActiveSB.fRawData.s_iextra do
  begin
    // Р—Р°РІР°РЅС‚Р°Р¶СѓС”РјРѕ Р±Р»РѕРєРё С‚Р° РґР°РЅС– Сѓ РІРЅСѓС‚СЂС–С€РЅС–Р№ Р±СѓС„РµСЂ
    LoadBlocks(blocks, indirect, size, fIExtraBlocks);
    SetLength(fIExtraRaw, size);
    LoadBlockData(fIExtraBlocks, @fIExtraRaw[0], size, fBlockSize);

    // Р—Р±РµСЂРµР¶РµРЅРЅСЏ Сѓ С„Р°Р№Р» РґР»СЏ Р°РЅР°Р»С–Р·Сѓ
    if size > 0 then
    begin
      FileStream := TFileStream.Create('qnx6_iextra_dump.bin', fmCreate);
      try
        FileStream.WriteBuffer(fIExtraRaw[0], size);
      finally
        FileStream.Free;
      end;
    end;
  end;
end;

procedure TQNX6Fs.LoadIClaim;
var
  i, c: integer;
begin
  with fActiveSB.fRawData.s_iclaim do
  begin
    LoadBlocks(blocks, indirect, size, fIClaimBlocks);
    SetLength(fIClaimRaw, size);
    LoadBlockData(fIClaimBlocks, @fIClaimRaw[0], size, fBlockSize);
  end;

end;


procedure TQNX6Fs.Close;
begin
  Flush;
end;

procedure TQNX6Fs.Flush;
var
  inode: TQNX6_DInode;
  idx, osize: dword;
  {$IFDEF USEGENERICS}
  Pair: specialize TPair<dword, TBytes>;
  {$ELSE}
  Pair: specialize TGMapEntry<dword, TBytes>;
  {$ENDIF}
  {$IFDEF DEBUG}
  ds : TFileStream;
  {$ENDIF}
begin
  if fChanged then
  begin
    with fActiveSB.fRawData do
    begin
      // Р›РѕРіСѓРІР°РЅРЅСЏ Р·РјС–РЅРµРЅРёС… С–РЅРѕРґС–РІ
      for idx in changedInodes do
        if cacheDInodes.TryGetValue(idx, inode) then
        begin
          // Р›РѕРіСѓРІР°РЅРЅСЏ РЅРѕРјРµСЂСѓ С–РЅРѕРґСѓ
          {$IFDEF DEBUG}
          WriteLn('Flushing inode: ', idx);  // Р›РѕРіСѓРІР°РЅРЅСЏ С–РЅРѕРґСѓ
          {$ENDIF}

          fStream.Position := inodePos(idx);
          fStream.Write(inode, SizeOf(TQNX6_DInode));
        end;
      changedInodes.Clear;

      // Р›РѕРіСѓРІР°РЅРЅСЏ Р·РјС–РЅРµРЅРёС… Р±Р»РѕРєС–РІ
      for Pair in changedBlocks do
      begin
        osize := Length(Pair.Value);
        // Р›РѕРіСѓРІР°РЅРЅСЏ СЃРµРєС‚РѕСЂСѓ (Р±Р»РѕРєСѓ)
        {$IFDEF DEBUG}
        WriteLn('Flushing block sector: ', Pair.Key, ' with size: ', osize);
        {$ENDIF}
        // Р›РѕРіСѓРІР°РЅРЅСЏ СЃРµРєС‚РѕСЂСѓ

        fStream.Position := dataStart + Pair.Key * fBlockSize;
        fStream.Write(Pair.Value[0], osize);
      end;
      changedBlocks.Clear;

      // Р—Р±РµСЂРµР¶РµРЅРЅСЏ Р±Р»РѕРєС–РІ РґРѕРІРіРёС… С–РјРµРЅ (СЏРєС‰Рѕ Р·РјС–РЅРё С”)
      fDirectWrite := True;
      if fChangedLong then
      begin
        SaveBlocks(lnames.blocks, fLongNameBlocks);
        lnames.size := fLongNameBlocks.level[0].Count * fBlockSize;
      end;

      // Р—Р±РµСЂРµР¶РµРЅРЅСЏ bitmap
      SaveBlockData(fBitmapBlocks, fBitmap.BitsPtr, bitmap.size, fBlockSize);
      fDirectWrite := False;
    end;

    // Р›РѕРіСѓРІР°РЅРЅСЏ Р·Р°РїРёСЃСѓ SuperBlock
    if fActiveSB = fSB0 then
    begin
      {$IFDEF DEBUG}
      WriteLn('Flushing SuperBlock for fSB0');
      {$ENDIF}
      fActiveSB.Write;
    end;

    // Р›РѕРіСѓРІР°РЅРЅСЏ Р·Р°РїРёСЃСѓ BootBlock
    if fBB <> nil then
      TQNX6_BootBlock(fBB).Write;

    fChanged := False;
  end;
end;


function TQNX6Fs.ReadDirectory(Path: string; var RDI: TQNX6_ARawDirEntry): integer;
var
  idx: DWord;
begin
  if Path = '' then
  begin
    Result := -ESysENOENT;
    Exit;
  end;

  idx := GetInodeByPath(PChar(Path));
  if idx = 0 then
  begin
    Result := -ESysENOENT;
    Exit;
  end;

  Result := ReadDirectory(idx, RDI);
end;

function TQNX6Fs.ReadDirectory(idx: DWord; var RDI: TQNX6_ARawDirEntry): integer;
var
  Blocks: TBlocksList;
  inode: TQNX6_DInode;
  i: integer;
begin
  SetLength(RDI, 0);

  if idx = 0 then
    Exit(-ESysENOENT);

  if cacheIDirs.TryGetValue(idx, RDI) then
    Exit(Length(RDI));

  inode := GetInode(idx);

  if not FpS_ISDIR(inode.mode) then
    Exit(-ESysENOTDIR);

  if inode.size = 0 then
    Exit(0);

  Result := inode.size div SizeOf(TQNX6_RawDirEntry);
  SetLength(RDI, Result);

  LoadInodeBlocks(idx, Blocks);
  LoadBlockData(Blocks, @RDI[0], inode.size, fBlockSize);

  // РћС‡РёСЃС‚РёС‚Рё РЅРµРІР°Р»С–РґРЅС– Р·Р°РїРёСЃРё (inode == 0 Р°Р±Рѕ $FFFFFFFF)
  for i := High(RDI) downto 0 do
    if (RDI[i].inode = 0) or (RDI[i].inode = $FFFFFFFF) then
      Delete(RDI, i, 1);

  Result := Length(RDI);

  if Result > 0 then
    cacheIDirs.AddOrSetValue(idx, RDI);
end;

function TQNX6Fs.WriteDirectory(idx: DWord; const RDI: TQNX6_ARawDirEntry): integer;
var
  Blocks: TBlocksList;
  entrySize, blockCount, totalSize: integer;
  buff: array of byte;
begin
  Result := -1;
  if idx = 0 then
    Exit;

  entrySize := Length(RDI) * SizeOf(TQNX6_RawDirEntry);
  blockCount := ifThen(entrySize = 0, 0, iceil(entrySize, fBlockSize));
  totalSize := blockCount * fBlockSize;

  // РћРЅРѕРІРёС‚Рё СЂРѕР·РјС–СЂ inode РїСЂРё Р·РјС–РЅС– СЂРѕР·РјС–СЂСѓ РґРёСЂРµРєС‚РѕСЂС–С—
  if Inodes[idx].size <> totalSize then
    SetSize(idx, totalSize);

  // РЇРєС‰Рѕ Р·Р°РїРёСЃС–РІ РЅРµРјР° вЂ” РїСЂРѕСЃС‚Рѕ РІРёРґР°Р»СЏС”РјРѕ Р· РєРµС€Сѓ
  if blockCount = 0 then
  begin
    cacheIDirs.Remove(idx);
    fChanged := True;
    Result := 0;
    Exit;
  end;

  // РџРёС€РµРјРѕ РІРјС–СЃС‚
  SetLength(buff, totalSize);
  if entrySize > 0 then
    Move(RDI[0], buff[0], entrySize);

  cacheIDirs.AddOrSetValue(idx, RDI);

  LoadInodeBlocks(idx, Blocks);
  SaveBlockData(Blocks, @buff[0], totalSize, fBlockSize);

  fChanged := True;
  Result := 0;
end;

function TQNX6Fs.GetInodeByPath(aName: pchar): DWord;
var
  bName, pathPart, fullPath: string;
  Dirs: array[0..127] of pchar;
  i, j, k, c, idx: integer;
  DE: TQNX6_ARawDirEntry;
  found: boolean;
begin
  Result := 0;
  if (aName = nil) or (aName^ = #0) then Exit;

  PathPart := aName;

  if PathPart = DirectorySeparator then
  begin
    Result := 1;
    Exit;
  end;

  if cacheInodes.TryGetValue(aName, Result) then Exit;

  c := GetDirs(PathPart, Dirs);
  if c > Length(Dirs) then Exit;

  idx := 1;
  fullPath := DirectorySeparator;

  for i := 0 to Pred(c) do
  begin
    found := False;
    k := ReadDirectory(idx, DE);
    if k < 0 then Exit;

    for j := 0 to Pred(k) do
    begin
      bName := RawDirEntryGetName(DE[j]);

      if (bName = '.') or (bName = '..') then
        Continue;

      if fullPath <> DirectorySeparator then
        fullPath := fullPath + DirectorySeparator + bName
      else
        fullPath := fullPath + bName;

      cacheInodes.AddOrSetValue(fullPath, DE[j].inode);

      if StrComp(Dirs[i], PChar(bName)) = 0 then
      begin
        found := True;
        idx := DE[j].inode;
        Break;
      end;
    end;

    if not found then
    begin
      Result := 0;
      Exit;
    end;
  end;

  Result := idx;
end;

function TQNX6Fs.GetLongName(idx: DWord; chk: DWord = 0): utf8string;
var
  blockIdx, chk2: DWord;
  tmp: TQNX6_LongName;
begin
  if idx >= fLongNameBlocks.level[0].Count then
    raise Exception.CreateFmt('GetLongName: invalid index (%d)', [idx]);

  blockIdx := fLongNameBlocks.level[0].Data[idx];
  ReadBlock(blockIdx, @tmp, SizeOf(TQNX6_LongName));

  // РЎС‚РІРѕСЂРµРЅРЅСЏ UTF-8 СЂСЏРґРєР° Р· С–РјвЂ™СЏ
  Result := Copy(PChar(@tmp.Name[0]), 1, tmp.len);

  // РљРѕРЅС‚СЂРѕР»СЊРЅР° СЃСѓРјР°
  if (chk <> 0) and ((fActiveSB.flags and QNX6FS_LFN_CKSUM) = QNX6FS_LFN_CKSUM) then
  begin
    chk2 := qnx6_lfile_checksum(@tmp.Name[0], tmp.len);
    //    if chk2 <> chk then
    //      raise Exception.CreateFmt('Long name checksum mismatch at idx %d (expected: %x, got: %x)',
    //        [int64(idx), int64(chk), int64(chk2)]);
  end;
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
      if j < fLongNames.Count then
        Result := GetLongName(j, longEntry^.cksum)
      else
        Result := 'DAMAGED LONG NAME ENTRY';
      //raise Exception.CreateFmt('RawDirEntryGetName: invalid longname index %d', [int64(j)]);
    end;

    1..QNX6FS_DIR_SHORT_LEN:
      Result := Copy(PChar(@entry.Data[0]), 1, entry.len);

    else
      Result := 'DAMAGED ENTRY'; // invalid or corrupt entry
  end;
end;


function TQNX6Fs.AddBlockToChain(var Blocks: TBlocksList; system: boolean = False): DWord;
var
  newBlock: TDwordArray;
  newIndexBlock: TDwordArray;
  blk: DWord;
begin
  if Blocks.level[0].Count >= fMaxBlocks then
  begin
    Result := 0;
    Exit;
  end;

  // Р”РѕРґР°С”РјРѕ Р·РІРёС‡Р°Р№РЅРёР№ Р±Р»РѕРє
  newBlock := AllocateBlocks(1, system);
  if Length(newBlock) = 0 then
  begin
    Result := 0;
    Exit;
  end;

  blk := newBlock[0];
  Result := blk;

  // Р’РёР·РЅР°С‡РµРЅРЅСЏ СЂС–РІРЅСЏ С–РЅРґРµРєСЃР°С†С–С—
  if Blocks.level[0].Count < QNX6FS_DIRECT_BLKS then
  begin
    Blocks.top := 0;
  end
  else
  begin
    // РџРѕС‚СЂС–Р±РµРЅ РїРµСЂРµС…С–Рґ РЅР° single indirect
    if (Blocks.level[1].Count < QNX6FS_DIRECT_BLKS) and
      ((Blocks.level[0].Count mod ptrs_in_block = 0) or (Blocks.level[0].Count =
      QNX6FS_DIRECT_BLKS)) then
    begin
      Blocks.top := 1;
      newIndexBlock := AllocateBlocks(1, system);
      Insert(newIndexBlock[0], Blocks.level[1].Data, Blocks.level[1].Count);
      Inc(Blocks.level[1].Count);
    end;

    // РџРѕС‚СЂС–Р±РµРЅ РїРµСЂРµС…С–Рґ РЅР° double indirect
    if (Blocks.level[2].Count < QNX6FS_DIRECT_BLKS) and
      ((Blocks.level[1].Count mod ptrs_in_block = 0) or (Blocks.level[1].Count =
      QNX6FS_DIRECT_BLKS)) then
    begin
      Blocks.top := 2;
      newIndexBlock := AllocateBlocks(1, system);
      Insert(newIndexBlock[0], Blocks.level[2].Data, Blocks.level[2].Count);
      Inc(Blocks.level[2].Count);
    end;
  end;

  // Р—Р°РїРёСЃ Р±Р»РѕРєСѓ Сѓ level 0
  Insert(blk, Blocks.level[0].Data, Blocks.level[0].Count);
  Inc(Blocks.level[0].Count);
end;

function TQNX6Fs.RemoveBlockFromChain(var Blocks: TBlocksList; id: DWord; idx: integer = -1): TDwordArray;
var
  c0_old, c1_old, i: integer;
  removed: DWord;
begin
  Result := [];
  c0_old := Blocks.level[0].Count;

  // РЇРєС‰Рѕ С–РЅРґРµРєСЃ РЅРµ РІРєР°Р·Р°РЅРѕ вЂ” С€СѓРєР°С”РјРѕ РїРѕ Р·РЅР°С‡РµРЅРЅСЋ
  if idx = -1 then
    for i := 0 to Pred(c0_old) do
      if Blocks.level[0].Data[i] = id then
      begin
        idx := i;
        Break;
      end;

  if (idx < 0) or (idx >= Blocks.level[0].Count) then Exit;

  // Р’РёРґР°Р»СЏС”РјРѕ СЃР°Рј Р±Р»РѕРє
  Delete(Blocks.level[0].Data, idx, 1);
  Dec(Blocks.level[0].Count);
  Result := [id];

  // РЇРєС‰Рѕ РІРёРєРѕСЂРёСЃС‚РѕРІСѓСЋС‚СЊСЃСЏ СЂС–РІРЅС– С–РЅРґРµРєСЃР°С†С–С—
  if Blocks.top > 0 then
  begin
    if iceil(Blocks.level[0].Count, ptrs_in_block) < iceil(c0_old, ptrs_in_block) then
    begin
      // РџРѕС‚СЂС–Р±РЅРѕ Р·РІС–Р»СЊРЅРёС‚Рё Р±Р»РѕРє 1-РіРѕ СЂС–РІРЅСЏ
      c1_old := Blocks.level[1].Count;
      Dec(Blocks.level[1].Count);
      removed := Blocks.level[1].Data[Blocks.level[1].Count];
      Delete(Blocks.level[1].Data, Blocks.level[1].Count, 1);

      Insert(removed, Result, 0);

      // РњРѕР¶Р»РёРІРѕ, С‚СЂРµР±Р° С‰Рµ Р№ Р±Р»РѕРє 2-РіРѕ СЂС–РІРЅСЏ
      if (Blocks.top = 2) and (iceil(Blocks.level[1].Count, ptrs_in_block) <
        iceil(c1_old, ptrs_in_block)) then
      begin
        Dec(Blocks.level[2].Count);
        removed := Blocks.level[2].Data[Blocks.level[2].Count];
        Delete(Blocks.level[2].Data, Blocks.level[2].Count, 1);
        Insert(removed, Result, 0);

        if Blocks.level[2].Count = 0 then
          Blocks.top := 1;
      end;

      if Blocks.level[1].Count = 0 then
        Blocks.top := 0;
    end;
  end;
end;

procedure TQNX6Fs.RawDirEntrySetName(var entry: TQNX6_RawDirEntry; NewName: utf8string);
var
  c, j, k: integer;
  chk: DWord;
  tmp: TQNX6_LongName;
  longEntry: PQNX6_LongNameEntry;
begin
  c := Length(NewName);
  if c > QNX6FS_NAME_MAX then
    raise Exception.CreateFmt('File name too long (%d > %d)', [c, QNX6FS_NAME_MAX]);

  FillChar(entry.Data[0], SizeOf(entry.Data), 0);

  // РЎРїРѕС‡Р°С‚РєСѓ вЂ” РґРѕРІРіРµ С–РјвЂ™СЏ
  if (c > QNX6FS_DIR_SHORT_LEN) then
  begin
    // РћС‚СЂРёРјР°С‚Рё Р°Р±Рѕ СЃС‚РІРѕСЂРёС‚Рё С–РЅРґРµРєСЃ РґРѕРІРіРѕРіРѕ С–РјРµРЅС–
    k := fLongNames.IndexOf(NewName);
    if k < 0 then
    begin
      j := AddBlockToChain(fLongNameBlocks);
      k := fLongNames.Add(NewName);

      if fDirectWrite then
        with fActiveSB.fRawData do
        begin
          lnames.indirect := fLongNameBlocks.top;
          SaveBlocks(lnames.blocks, fLongNameBlocks);
          lnames.size := fLongNameBlocks.level[0].Count * fBlockSize;
        end
      else
        fChangedLong := True;
    end;

    // Р—Р°РїРёСЃ РјРµС‚Р°-С–РЅС„РѕСЂРјР°С†С–С— РїСЂРѕ С–РјвЂ™СЏ
    longEntry := PQNX6_LongNameEntry(@entry.Data[0]);
    longEntry^.blkno := k;
    entry.len := QNX6FS_DIR_LONGNAME;

    FillChar(tmp.Name[0], SizeOf(tmp.Name), 0);
    tmp.len := c;
    Move(NewName[1], tmp.Name[0], c);

    if fActiveSB.flags and QNX6FS_LFN_CKSUM = QNX6FS_LFN_CKSUM then
      chk := qnx6_lfile_checksum(@tmp.Name[0], tmp.len)
    else
      chk := 0;

    longEntry^.cksum := chk;
    WriteBlock(fLongNameBlocks.level[0].Data[k], @tmp, SizeOf(TQNX6_LongName));
    if not fDirectWrite then
      fChangedLong := True;
  end
  else
  begin
    // РљРѕСЂРѕС‚РєРµ С–РјвЂ™СЏ
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
  for i := 0 to high(RDI) do
  begin
    if (RDI[i].inode <> 0) and (RDI[i].inode <> $FFFFFFFF) then
    begin
      bName := RawDirEntryGetName(RDI[i]);
      if bName = Name then
        exit(i);
    end;
  end;
end;

function TQNX6Fs.AllocateBlocks(Count: integer; System: boolean = False): TDwordArray;
var
  blockNo: DWord;
  n, found: integer;
begin
  SetLength(Result, 0); // СЏРІРЅР° С–РЅС–С†С–Р°Р»С–Р·Р°С†С–СЏ

  if Count <= 0 then
    Exit;

  if Count > fActiveSB.fRawData.free_blocks then
    Exit;

  found := 0;
  SetLength(Result, Count);

  {$IFDEF USEGENERICS}
  while (fFreeBlocks.Count > 0) and (found < Count) do
  begin
    blockNo := fFreeBlocks.Dequeue;
    fBitmap.SetOn(blockNo);
    Result[found] := blockNo;
    Inc(found);
  end;
  {$ELSE}
  while (found < Count) do
  begin
    if not fFreeBlocks.TryDequeue(blockNo) then Break;
    fBitmap.SetOn(blockNo);
    Result[found] := blockNo;
    Inc(found);
    Dec(fActiveSB.fRawData.free_blocks);
  end;
  {$ENDIF}

  // Р”РѕР·Р°РїРѕРІРЅРµРЅРЅСЏ С‡РµСЂРµР· bitmap, СЏРєС‰Рѕ РїРѕС‚СЂС–Р±РЅРѕ
  if found < Count then
  begin
    if System then
      n := fBitmap.FindFirstBit(False)
    else
    begin
      fBitmap.SetIndex(fUserAreaStart - 1);
      n := fBitmap.FindNextBit;
    end;

    while (n <> -1) do
    begin
      fBitmap.SetOn(n);
      Result[found] := n;
      Inc(found);
      Dec(fActiveSB.fRawData.free_blocks);
      if found = Count then Break;
      n := fBitmap.FindNextBit;
    end;
  end;

  if found < Count then
    SetLength(Result, found); // РџРѕРІРµСЂС‚Р°С”РјРѕ Р»РёС€Рµ РґРѕСЃС‚СѓРїРЅС– Р±Р»РѕРєРё

  if found > 0 then
    fChanged := True
  else
    SetLength(Result, 0); // fallback
end;

procedure TQNX6Fs.FreeBlocks(blocks: TDwordArray);
var
  k: DWord;
  total: DWord;
begin
  total := fActiveSB.fRawData.num_blocks;

  for k in blocks do
  begin
    if k >= total then Continue; // Р—Р°С…РёСЃС‚ РІС–Рґ РІРёС…РѕРґСѓ Р·Р° РјРµР¶С–

    fBitmap.Clear(k);
    fFreeBlocks.Enqueue(k);
    changedBlocks.Remove(k);
    Inc(fActiveSB.fRawData.free_blocks);
  end;

  fChanged := True;
end;


procedure TQNX6Fs.ReadBlock(idx: DWord; buff: Pointer; isize: DWord = 0);
var
  Data: TBytes;
  blockSizeToRead: DWord;
  translatedIdx: QWord;
  readCount: integer;
begin
  if buff = nil then Exit;

  // Р’РёР·РЅР°С‡РµРЅРЅСЏ С„Р°РєС‚РёС‡РЅРѕРіРѕ СЂРѕР·РјС–СЂСѓ С‡РёС‚Р°РЅРЅСЏ
  if isize = 0 then
    blockSizeToRead := fBlockSize
  else
    blockSizeToRead := isize;

  translatedIdx := idx;

  // РџРµСЂРµРІС–СЂРєР° РЅР° РїРµСЂРµРїРѕРІРЅРµРЅРЅСЏ С– РјРµР¶С–
  if translatedIdx > (High(QWord) div fBlockSize) then
    raise Exception.Create('Block index too large');

  fStream.Position := dataStart + translatedIdx * QWord(fBlockSize);

  // Р‘РµР·РїРµС‡РЅРµ С‡РёС‚Р°РЅРЅСЏ
  readCount := fStream.Read(buff^, blockSizeToRead);
  if readCount < blockSizeToRead then
    FillChar(pbyte(buff)[readCount], blockSizeToRead - readCount, 0);

  // РЇРєС‰Рѕ Р±Р»РѕРє Р·РјС–РЅРµРЅРёР№ вЂ“ РѕРЅРѕРІР»СЋС”РјРѕ
  if changedBlocks.TryGetValue(idx, Data) then
  begin
    if Length(Data) < blockSizeToRead then
    begin
      // Р—Р°С…РёСЃС‚ РІС–Рґ РїРµСЂРµРїРёСЃСѓРІР°РЅРЅСЏ Р»РёС€Рµ С‡Р°СЃС‚РёРЅРё Р±СѓС„РµСЂР°
      Move(Data[0], buff^, Length(Data));
      FillChar(pbyte(buff)[Length(Data)], blockSizeToRead - Length(Data), 0);
    end
    else
      Move(Data[0], buff^, blockSizeToRead);
  end;
end;


procedure TQNX6Fs.EraseInode(idx: DWord);
var
  dinode: TQNX6_DInode;
begin
  // РџРµСЂРµРІС–СЂРєР° РЅР° РєРѕСЂРµРєС‚РЅРёР№ С–РЅРґРµРєСЃ
  if (idx = 0) or (idx > fActiveSB.num_inodes) then
    Exit;

  dinode := Default(TQNX6_DInode);
  // РћР±РЅСѓР»РёС‚Рё С–РЅРѕРґ
  SetInode(idx, dinode);

  // Р”РѕРґР°С‚Рё РґРѕ С‡РµСЂРіРё РІС–Р»СЊРЅРёС… С–РЅРѕРґС–РІ
  fFreeInodes.Enqueue(idx);

  Inc(fActiveSB.fRawData.free_inodes);

  // РћС‡РёСЃС‚РёС‚Рё РєРµС€С–
  cacheDInodes.AddOrSetValue(idx, dinode);
  cacheBlocksChains.Remove(idx);
  //cacheBlocksChains.AddOrSetValue(idx, Default(TBlocksList));
  UsedInodesList.Remove(idx); // СЏРєС‰Рѕ С–СЃРЅСѓС”

  fChanged := True;

  {$IFDEF DEBUG}
  WriteLn('Erased inode: ', idx);
  {$ENDIF}
end;

procedure TQNX6Fs.WriteBlock(idx: DWord; buff: Pointer; osize: DWord = 0);
var
  Data: TBytes;
  sizeToWrite: DWord;
begin
  if buff = nil then Exit;

  if osize = 0 then
    sizeToWrite := fBlockSize
  else
    sizeToWrite := osize;

  if fDirectWrite then
  begin
    fStream.Position := dataStart + idx * fBlockSize;
    fStream.Write(buff^, sizeToWrite);
  end
  else
  begin
    SetLength(Data, sizeToWrite);
    Move(buff^, Data[0], sizeToWrite);
    changedBlocks.AddOrSetValue(idx, Data);
  end;
end;

constructor TQNX6Fs.Create(Stream: TStream);
begin
  fStream := Stream;
  fInodesLoaded := False;
  fLastPos := MaxInt;

  fFreeBlocks := TFreeBlocks.Create;
  fFreeInodes := TFreeBlocks.Create;

  {$IFDEF USEGENERICS}
  cacheInodes := TCachedInodes.Create;
  cacheDInodes := TCachedDInodes.Create;
  cacheIDirs := TCachedIDirs.Create;
  cacheBlocksChains := TBlocksChains.Create;

  changedInodes := TChangedList.Create;
  changedInodes.Duplicates := dupIgnore;
  changedInodes.Sorted := True;
  changedBlocks := TChangedBlocks.Create;
  UsedInodesList := TUsedInodes.Create;
  UsedInodesList.Duplicates := dupIgnore;
  UsedInodesList.Sorted := True;
  {$ELSE}
  changedInodes.RejectDuplicates := True;
  UsedInodesList.RejectDuplicates := True;
  {$ENDIF}

  fDirectWrite := False;
  fChanged := False;
  fChangedLong := False;
  fBitmap := XBits.Create();
  fLongNames := TStringList.Create;
end;

destructor TQNX6Fs.Destroy;
begin
  {$IFDEF USEGENERICS}
  FreeAndNil(cacheBlocksChains);
  FreeAndNil(cacheIDirs);
  FreeAndNil(cacheInodes);
  FreeAndNil(cacheDInodes);


  FreeAndNil(changedInodes);
  FreeAndNil(changedBlocks);
  FreeAndNil(UsedInodesList);
  {$ENDIF}
  FreeAndNil(fFreeBlocks);
  FreeAndNil(fFreeInodes);

  FreeAndNil(fLongNames);
  FreeAndNil(fBitmap);
  FreeAndNil(fSB1);
  FreeAndNil(fSB0);
  FreeAndNil(fBB);
  fActiveSB := nil;
  inherited;
end;


function TQNX6Fs.CompactBlocks: integer;
type
  {$IFDEF USEGENERICS}
  TDynArray = specialize TList<DWord>;
  TMap      = specialize TDictionary<DWord, DWord>;
  {$ELSE}
  TDynArray = specialize TGVector<DWord>;
  TMapType = specialize TGLiteHashMapLP<DWord, DWord, DWord>;
  TMap = TMapType.TMap;
  {$ENDIF}
var
  maxBlock, lu, ff: DWord;
  Buff: TBytes;
  BlocksMoved, i: integer;
  fromBlocks, toBlocks: TDynArray;
  spinner, progress: IProgressIndicator;

  FirstFreePos, LastUsedPos: DWord;

  function FirstFree: DWord;
  var
    pos: DWord;
  begin
    // Find first free block starting from FirstFreePos
    for pos := FirstFreePos to maxBlock - 1 do
      if not fBitmap.Bits[pos] then
      begin
        FirstFreePos := pos + 1;
        Exit(pos);
      end;
    Result := maxBlock; // No free block found
  end;

  function LastUsed: DWord;
  var
    pos: DWord;
  begin
    // Find last used block starting from LastUsedPos
    for pos := LastUsedPos downto fUserAreaStart do
      if fBitmap.Bits[pos] then
      begin
        LastUsedPos := pos - 1;
        Exit(pos);
      end;
    Result := fUserAreaStart; // No used block found
  end;

  procedure ReplaceInBlocksChains;
  var
    i, j: integer;
    v: DWord;
    Map: TMap;
    Blocks: TBlocksList;
    {$IFDEF USEGENERICS}
    Pair: specialize TPair<DWord, TQNX6_DInode>;
    {$ELSE}
    Pair: specialize TGMapEntry<DWord, TQNX6_DInode>;
    {$ENDIF}
    modified: boolean;
  begin
    {$IFDEF USEGENERICS}
    Map := TMap.Create;
    {$ELSE}
    Map.Clear; // Properly initialize map in non-generic mode
    {$ENDIF}
    try
      // Build map of old->new block positions
      for i := 0 to fromBlocks.Count - 1 do
        Map.Add(fromBlocks[i], toBlocks[i]);

      // Update block references in cached inodes
      for Pair in cacheDInodes do
      begin
        LoadInodeBlocks(Pair.Key, Blocks);
        modified := False;
        for i := 0 to High(Blocks.level) do
          for j := 0 to Blocks.level[i].Count - 1 do
            if Map.TryGetValue(Blocks.level[i].Data[j], v) then
            begin
              Blocks.level[i].Data[j] := v;
              modified := True;
            end;
        if modified then
          SaveInodeBlocks(Pair.Key, Pair.Value.size, Blocks);
      end;

      // Update long filename block references
      modified := False;
      for i := 0 to High(fLongNameBlocks.level) do
        for j := 0 to fLongNameBlocks.level[i].Count - 1 do
          if Map.TryGetValue(fLongNameBlocks.level[i].Data[j], v) then
          begin
            fLongNameBlocks.level[i].Data[j] := v;
            modified := True;
          end;
      if modified then
        fChangedLong := True;

    finally
      {$IFDEF USEGENERICS}
      Map.Free;
      {$ELSE}
      Map.Clear; // Free resources for non-generic map
      {$ENDIF}
    end;
  end;

begin
  Result := 0;
  if not fInodesLoaded then
    PreloadInodes(True);

  // Calculate maximum usable block index
  maxBlock := Min(fBitmap.Size, (fStream.Size - dataStart) div fBlockSize);

  // Initialize search positions
  FirstFreePos := fUserAreaStart;
  LastUsedPos := maxBlock - 1;

  lu := LastUsed;
  ff := FirstFree;

  // If no compaction needed, shrink file size and exit
  if lu <= ff then
  begin
    fStream.Size := dataStart + lu * fBlockSize;
    TConsole.WriteLn(Format('   %d => %d   (%d bytes)', [ff, lu, fStream.Size]));
    Exit(0);
  end;

  TConsole.WriteLn('Compacting blocks...');
  SetLength(Buff, fBlockSize);
  fromBlocks := TDynArray.Create;
  toBlocks := TDynArray.Create;
  BlocksMoved := 0;

  spinner := CreateSpinner(ssDots);
  TConsole.WriteLn('Finding block move pairs...');
  spinner.Start;

  // Build list of block moves
  while (lu > ff) do
  begin
    fromBlocks.Add(lu);
    toBlocks.Add(ff);
    Inc(BlocksMoved);

    if (BlocksMoved and $3FF) = 0 then
    begin
      spinner.Update(0);
      TConsole.Write(Format('   %d => %d', [ff, lu]));
    end;

    lu := LastUsed;
    ff := FirstFree;
  end;
  spinner.Stop;

  if BlocksMoved > 0 then
  begin
    TConsole.WriteLn('Updating block references...');
    ReplaceInBlocksChains;

    fDirectWrite := True;
    TConsole.WriteLn('Moving block data...');
    progress := CreateProgressBar(fromBlocks.Count, 50);
    progress.Start;

    for i := 0 to fromBlocks.Count - 1 do
    begin
      if (i and $3FF) = 0 then
        progress.Update(i);
      ReadBlock(fromBlocks[i], @Buff[0]);
      WriteBlock(toBlocks[i], @Buff[0]);

      fBitmap.Bits[fromBlocks[i]] := False;
      fBitmap.Bits[toBlocks[i]] := True;
    end;

    progress.Stop;
    fDirectWrite := False;

    TConsole.WriteLn(Format('Blocks moved: %d', [BlocksMoved]));
    Result := BlocksMoved;

    if fChanged or fChangedLong or (BlocksMoved > 0) then
    begin
      Flush;
      fStream.Size := dataStart + ff * fBlockSize;
    end;
  end;

  fromBlocks.Free;
  toBlocks.Free;
  Finalize(Buff);
end;


function TQNX6Fs.InodeUsed(idx: DWord): boolean;
var
  dinode: TQNX6_DInode;
begin
  // РџРµСЂРµРІС–СЂРєР° РЅР° РјРµР¶С–
  if (idx = 0) or (idx > fActiveSB.num_inodes) then
    Exit(False);

  dinode := GetInode(idx);
  Result := dinode.mode <> 0;
end;


function TQNX6Fs.CompactInodes: integer;
type
  {$IFDEF USEGENERICS}
  TInodeRemap = specialize TDictionary<DWord, DWord>;
  {$ELSE}
  TInodeRemapType = specialize TGLiteHashMapLP<DWord, DWord, DWord>;
  TInodeRemap = TInodeRemapType.TMap;
  {$ENDIF}
var
  i, j: integer;
  oldIdx, newIdx: DWord;
  inode: TQNX6_DInode;
  dirEntries: TQNX6_ARawDirEntry;
  InodeRemap: TInodeRemap;
  remapKeys: array of DWord;
  eraseList: array of DWord;
  totalUsed: DWord;
  progress: IProgressIndicator;
  changed: boolean;
  entryIdx: DWord;
  maxInodes: DWord;
begin
  Result := 0;

  PreloadInodes(True);

  maxInodes := TQNX6_SuperBlock(fActiveSB).num_inodes;
  totalUsed := maxInodes - TQNX6_SuperBlock(fActiveSB).free_inodes;
  if totalUsed = 0 then Exit(0);

  TConsole.WriteLn('--- QNX6 inode compaction start ---');

  {$IFDEF USEGENERICS}
  InodeRemap := TInodeRemap.Create;
  {$ELSE}
  InodeRemap.Clear;
  {$ENDIF}

  // =====================================================
  // 1) Build old \u2192 new remap
  // =====================================================
  for newIdx := 1 to UsedInodesList.Count do
  begin
    oldIdx := UsedInodesList[newIdx - 1];
    if oldIdx <> newIdx then
      InodeRemap.Add(oldIdx, newIdx);
  end;

  if InodeRemap.Count = 0 then
  begin
    {$IFDEF USEGENERICS}
 InodeRemap.Free;
    {$ENDIF}
    Exit(0);
  end;

  // snapshot keys (stable)
  SetLength(remapKeys, InodeRemap.Count);
  i := 0;
  for oldIdx in InodeRemap.Keys do
  begin
    remapKeys[i] := oldIdx;
    Inc(i);
  end;

  // =====================================================
  // 2) Update ALL directory entries (BEFORE inode move)
  // =====================================================
  TConsole.WriteLn('Updating directory entries...');
  progress := TProgressBar.Create(maxInodes, 50);
  progress.Start;

  for oldIdx := 1 to maxInodes do
  begin
    progress.Update(oldIdx);

    if not InodeUsed(oldIdx) then Continue;
    if not FpS_ISDIR(Inodes[oldIdx].mode) then Continue;

    ReadDirectory(oldIdx, dirEntries);
    changed := False;

    for j := 0 to High(dirEntries) do
    begin
      // "." and ".." must stay intact logically
      if dirEntries[j].inode <= 1 then Continue;

      if InodeRemap.TryGetValue(dirEntries[j].inode, entryIdx) then
      begin
        dirEntries[j].inode := entryIdx;
        changed := True;
        Inc(Result);
      end;
    end;

    if changed then
      WriteDirectory(oldIdx, dirEntries);
  end;

  progress.Stop;

  // =====================================================
  // 3) Physically move inodes (HIGH \u2192 LOW)
  // =====================================================
  TConsole.WriteLn('Moving inode table...');
  progress := TProgressBar.Create(Length(remapKeys), 50);
  progress.Start;

  SetLength(eraseList, Length(remapKeys));

  for i := High(remapKeys) downto 0 do
  begin
    oldIdx := remapKeys[i];
    InodeRemap.TryGetValue(oldIdx, newIdx);

    progress.Update(Length(remapKeys) - i);

    inode := GetInode(oldIdx);
    SetInode(newIdx, inode);

    eraseList[High(remapKeys) - i] := oldIdx;
  end;

  progress.Stop;

  // =====================================================
  // 4) Erase old inode slots
  // =====================================================
  TConsole.WriteLn('Erasing old inodes...');
  for i := 0 to High(eraseList) do
    EraseInode(eraseList[i]);

  // =====================================================
  // 5) Rebuild UsedInodesList
  // =====================================================
  UsedInodesList.Clear;
  for i := 1 to totalUsed do
    UsedInodesList.Add(i);

  {$IFDEF USEGENERICS}
  InodeRemap.Free;
  {$ELSE}
  InodeRemap.Clear;
  {$ENDIF}

  SetLength(remapKeys, 0);
  SetLength(eraseList, 0);

  TConsole.WriteLn('--- inode compaction finished ---');
end;


procedure TQNX6Fs.CreateImage(blocks, blockSize, inodes: integer);
var
  i, r1, r2, r3, r4, used: integer;
  sb: TQNX6_SuperBlock;
  r_inode, b_inode: TQNX6_DInode;
  rootBlock, bootBlock: TDwordArray;

  Data: TBytes;
begin
  if (blockSize mod 512) <> 0 then exit;
  if inodes * SizeOf(TQNX6_DInode) > blocks * blockSize then exit;
  fStream.Size := 0;
  fStream.Position := 0;
  fBlockSize := blockSize;
  PDword(@bootsect[12])^ := blocks * blockSize;
  fStream.Write(bootsect[0], SizeOf(bootsect));
  fBB := nil;
  sb := TQNX6_SuperBlock.Create(fStream);
  sb.selfPos := $2000;

  if fBlockSize <= 4096 then
    dataStart := QNX6FS_BOOT_RSRV + QNX6FS_SBLK_RSRV
  else
    dataStart := QNX6FS_BOOT_RSRV + QNX6FS_SBLK_RSRV + abs(QNX6FS_BOOT_RSRV +
      QNX6FS_SBLK_RSRV - fBlockSize);

  try
    fActiveSB := sb;
    FillChar(sb.fRawData, SizeOf(TQNX6_SuperBlockRaw), 0);

    ptrs_in_block := fBlockSize div 4;
    fMaxBlocks := QNX6FS_DIRECT_BLKS * ptrs_in_block * ptrs_in_block;
    fBitmap.Size := Blocks;

    r1 := inodes * SizeOf(TQNX6_DInode);
    r2 := iceil(r1, fBlockSize);
    // inodes direct blocks
    r3 := iceil(blocks, 8);
    // bitmap bytes
    r4 := iceil(r3, fBlockSize);

    fSys0AreaStart := 0;
    fSys1AreaStart := (r2 + NeededExtraBlocks(r2) + r4 + NeededExtraBlocks(r4));
    fUserAreaStart := 2 * fSys1AreaStart;
    fFirstFreeInode := 1;
    sb.Magic := QNX6FS_SIGNATURE2;
    CreateGUID(sb.fRawData.volumeid);
    sb.Serial := 1;
    sb.version := QNX6FS_FSYS_VERSION;
    sb.rsrvblks := QNX6FS_DEFAULT_RSRV;
    sb.blocksize := blockSize;
    sb.num_inodes := inodes;
    sb.free_inodes := inodes - 2;
    sb.allocgroup := 16;
    sb.num_blocks := blocks;
    sb.free_blocks := blocks - fUserAreaStart;

    sb.fRawData.lnames.size := 0;
    FillDWord(sb.fRawData.lnames.blocks, 16, $FFFFFFFF);

    fInodesBlocks := Default(TBlocksList);
    fBitmapBlocks := Default(TBlocksList);
    fLongNameBlocks := Default(TBlocksList);

    for i := 1 to r2 do AddBlockToChain(fInodesBlocks, True);
    for i := 1 to r4 do AddBlockToChain(fBitmapBlocks, True);

    r_inode := Default(TQNX6_DInode);
    r_inode.size := fBlockSize;

    b_inode := Default(TQNX6_DInode);
    b_inode.size := fBlockSize;
    FillDWord(r_inode.blocks, 16, $FFFFFFFF);
    FillDWord(b_inode.blocks, 16, $FFFFFFFF);

    RootBlock := AllocateBlocks(1, True);
    BootBlock := AllocateBlocks(1, True);

    r_inode.mode := &777 or S_IFDIR;
    b_inode.mode := &744 or S_IFDIR;

    r_inode.nlink := 3;
    r_inode.blocks[0] := rootBlock[0];
    b_inode.blocks[0] := bootBlock[0];
    b_inode.nlink := 2;

    SetLength(Data, fBlockSize);

    (PDword(@Data[0]) + 00)^ := 2;
    (PDword(@Data[0]) + 01)^ := $2e01;
    (PDword(@Data[0]) + 08)^ := 1;
    (PDword(@Data[0]) + 09)^ := $2e2e02;
    WriteBlock(BootBlock[0], @Data[0]);

    (PDword(@Data[0]) + 00)^ := 1;
    (PDword(@Data[0]) + 16)^ := 2;
    (PDword(@Data[0]) + 17)^ := $6f622e05;
    (PDword(@Data[0]) + 18)^ := $746f;
    WriteBlock(RootBlock[0], @Data[0]);

    SetInode(1, r_inode);
    SetInode(2, b_inode);

    sb.fRawData.bitmap.size := r3;
    sb.fRawData.bitmap.indirect := fBitmapBlocks.top;
    SaveBlocks(sb.fRawData.bitmap.blocks, fBitmapBlocks);
    sb.fRawData.inodes.size := r1;
    sb.fRawData.inodes.indirect := fInodesBlocks.top;
    SaveBlocks(sb.fRawData.inodes.blocks, fInodesBlocks);
    Flush;
    sb.Write;
  finally
    FreeAndNil(sb);
  end;
end;

function TQNX6Fs.GetFreeInodeCount: integer; inline;
begin
  Result := fActiveSB.fRawData.free_inodes;
end;

function TQNX6Fs.GetFreeBlockCount: integer; inline;
begin
  Result := fActiveSB.fRawData.free_blocks;
end;


function TQNX6Fs.GetInodeCount: integer; inline;
begin
  Result := fActiveSB.fRawData.num_inodes;
end;

function TQNX6Fs.GetBlockCount: integer; inline;
begin
  Result := fActiveSB.fRawData.num_blocks;
end;

procedure TQNX6Fs.Fsck(var Errors: TStringList; Fix: boolean = False);
type
  {$IFDEF USEGENERICS}
  TCache = specialize TDictionary<DWord, Integer>;
  {$ELSE}
  TCacheType = specialize TGLiteHashMapLP<DWord, integer, DWord>;
  TCache = TCacheType.TMap;
  {$ENDIF}
var
  i, j: DWord;
  target, Inode: TQNX6_DInode;
  Blocks: TBlocksList;
  DE: TQNX6_ARawDirEntry;
  seenBlocks, claimedBlocks: TBits;
  blk: DWord;
  usedLinks: TCache;
  fInodeCount, actualNlink: integer;
  ln, Name: utf8string;
  HasDot, HasDotDot: boolean;
  UnusedInodes: integer;
  TotalFileSize: int64;      // <-- РґРѕРґР°РЅРѕ
  ImageSize: int64;          // <-- РґРѕРґР°РЅРѕ
begin
  if not Assigned(Errors) then
    Errors := TStringList.Create;
  seenBlocks := TBits.Create(fBitmap.Size);
  claimedBlocks := TBits.Create(fBitmap.Size);

  {$IFDEF USEGENERICS}
  usedLinks := TCache.Create;
  {$ELSE}
  usedLinks.Clear;
  {$ENDIF}

  UnusedInodes := 0;
  TotalFileSize := 0;

  try
    if (not assigned(fActiveSB)) or (not fActiveSB.isValid) then
      raise Exception.Create('Filesystem not initialized or invalid superblock');

    //if not fInodesLoaded then
    PreloadInodes(True);

    TConsole.WriteLn('в†’ Checking inodes');
    for i in UsedInodesList do
    begin
      Inode := GetInode(i);

      if Inode.mode = 0 then
      begin
        Errors.Add(Format('вќЊ Inode #%d has zero mode (uninitialized)', [i]));
        Continue;
      end;

      if Inode.size > fMaxBlocks * fBlockSize then
        Errors.Add(Format('вќЊ Inode #%d: size too large (%d bytes)', [int64(i), int64(Inode.size)]));

      // РџС–РґСЂР°С…СѓРЅРѕРє Р·Р°РіР°Р»СЊРЅРѕРіРѕ СЂРѕР·РјС–СЂСѓ С„Р°Р№Р»С–РІ
      Inc(TotalFileSize, Inode.size);

      LoadInodeBlocks(i, Blocks);
      for j := 0 to Blocks.top do
        for blk in Blocks.level[j].Data do
        begin
          if (blk >= fBitmap.Size) then
            Errors.Add(Format('вќЊ Inode #%d references out-of-range block %d', [int64(i), int64(blk)]))
          else
          begin
            if blk <> 0 then
            begin
              if seenBlocks[blk] then
                Errors.Add(Format('вќЊ Duplicate block %d referenced by inode #%d', [int64(blk), int64(i)]))
              else
                seenBlocks[blk] := True;

              claimedBlocks[blk] := True;
            end;
          end;
        end;
    end;

    TConsole.WriteLn('в†’ Checking directories');
    for i in UsedInodesList do
    begin
      Inode := GetInode(i);
      if FpS_ISDIR(Inode.mode) then
      begin
        if ReadDirectory(i, DE) < 0 then
        begin
          Errors.Add(Format('вќЊ Failed to read directory at inode #%d', [i]));
          Continue;
        end;

        HasDot := False;
        HasDotDot := False;
        if (DE <> nil) then
          for j := 0 to High(DE) do
          begin

            if not isValidInode(DE[j].inode) then
              Errors.Add(Format('вќЊ Directory inode #%d references invalid inode %d ("%s")',
                [int64(i), int64(DE[j].inode), Name]))
            else
            begin
              Name := RawDirEntryGetName(DE[j]);

              if Name = '.' then HasDot := True;
              if Name = '..' then HasDotDot := True;

              if Copy(Name, 1, 7) = 'DAMAGED' then
                Errors.Add(Format('вќЊ Directory #%d contains entry "%s" pointing to unallocated inode %d',
                  [i, Name, DE[j].inode]))
              else if not UsedInodesList.Contains(DE[j].inode) then
                Errors.Add(Format('вќЊ Directory #%d contains entry "%s" pointing to unallocated inode %d',
                  [i, Name, DE[j].inode]))
              else
              begin
                target := GetInode(DE[j].inode);
                if target.mode = 0 then
                  Errors.Add(Format('вќЊ Directory #%d entry "%s" points to cleared inode #%d (mode = 0)',
                    [i, Name, DE[j].inode]));

                if (Name = '.') and (DE[j].inode <> i) then
                  Errors.Add(Format('вќЊ Directory #%d: "." entry points to inode #%d instead of self',
                    [i, DE[j].inode]));

                if (Name = '..') and (i = 1) and (DE[j].inode <> 1) then
                  Errors.Add(Format('вќЊ Root directory ".." must point to itself (inode 1), got %d',
                    [DE[j].inode]));
              end;
            end;

            {$IFDEF USEGENERICS}
            if usedLinks.ContainsKey(DE[j].inode) then
              usedLinks[DE[j].inode] := usedLinks[DE[j].inode] + 1
            else
              usedLinks.Add(DE[j].inode, 1);
            {$ELSE}
            if usedLinks.Contains(DE[j].inode) then
              usedLinks.Items[DE[j].inode] := usedLinks.Items[DE[j].inode] + 1
            else
              usedLinks.Add(DE[j].inode, 1);
            {$ENDIF}
          end;

        if not HasDot then Errors.Add(Format('вќЊ Directory #%d missing "." entry', [i]));
        if not HasDotDot then Errors.Add(Format('вќЊ Directory #%d missing ".." entry', [i]));
      end;
    end;

    TConsole.WriteLn('в†’ Checking link counts');
    for i in UsedInodesList do
    begin
      Inode := GetInode(i);
      {$IFDEF USEGENERICS}
      if usedLinks.TryGetValue(i, actualNlink) then
      begin
      {$ELSE}
      if usedLinks.Contains(i) then
      begin
        actualNlink := usedLinks.Items[i];
      {$ENDIF}
        if Inode.nlink <> actualNlink then
        begin
          Errors.Add(Format('вќЊ Inode #%d: nlink=%d, actual references=%d', [i, Inode.nlink, actualNlink]));
          if Fix then
          begin
            Inode.nlink := actualNlink;
            SetInode(i, Inode);
          end;
        end;
      end
      else if Inode.nlink > 0 then
      begin
        Errors.Add(Format('вќЊ Inode #%d: has nlink=%d but no directory references', [i, Inode.nlink]));
        if Fix then
        begin
          Inode.nlink := 0;
          SetInode(i, Inode);
        end;
      end;
    end;

    TConsole.WriteLn('в†’ Checking for orphan initialized inodes');
    fInodeCount := GetInodeCount;
    for i := 0 to fInodeCount - 1 do
    begin
      if (not UsedInodesList.Contains(i)) and isValidInode(i) then
      begin
        Inode := GetInode(i);
        if Inode.mode <> 0 then
          Errors.Add(Format('вљ  Inode #%d is initialized (mode=%o) but unused (orphan)', [i, Inode.mode]));
      end;
    end;

    TConsole.WriteLn('в†’ Counting unused but initialized inodes');
    for i := 1 to fInodeCount - 1 do
    begin
      if not UsedInodesList.Contains(i) then
      begin
        Inode := GetInode(i);
        if Inode.mode <> 0 then
          Inc(UnusedInodes);
      end;
    end;
    if UnusedInodes > 0 then
      TConsole.WriteLn(Format('вљ  Found %d unused but initialized inodes', [UnusedInodes]));

    if fLongNameBlocks.level[0].Count > 0 then
    begin
      TConsole.WriteLn('в†’ Checking long names');
      for i := 0 to fLongNameBlocks.level[0].Count - 1 do
      begin
        try
          ln := GetLongName(i);
          if ln = '' then
            Errors.Add(Format('вљ  Empty longname at block #%d', [i]));
        except
          on E: Exception do
            Errors.Add(Format('вќЊ Invalid longname at block %d: %s', [i, E.Message]));
        end;
      end;

      TConsole.WriteLn('в†’ Marking longname blocks as used');
      for j := 0 to fLongNameBlocks.top do
      begin
        for i := 0 to fLongNameBlocks.level[j].Count - 1 do
        begin
          blk := fLongNameBlocks.level[j].Data[i];
          if blk < fBitmap.Size then
            claimedBlocks[blk] := True
          else
            Errors.Add(Format('вќЊ Longname block %d out of range (level %d)', [blk, j]));
        end;
      end;
    end;

    TConsole.WriteLn('в†’ Checking bitmap consistency');
    for i := fUserAreaStart to fBitmap.Size - 1 do
    begin
      if fBitmap.Bits[i] and (not claimedBlocks[i]) then
      begin
        Errors.Add(Format('вќЊ Block %d is marked used in bitmap but not referenced by any inode', [i]));
        if Fix then fBitmap.Clear(i);
      end;

      if (not fBitmap.Bits[i]) and claimedBlocks[i] then
      begin
        Errors.Add(Format('вќЊ Block %d is referenced by inodes but not marked used in bitmap', [i]));
        if Fix then fBitmap.SetOn(i);
      end;
    end;


    // --- Р”РѕРґР°РЅРѕ Р±Р»РѕРє РїРѕСЂС–РІРЅСЏРЅРЅСЏ СЂРѕР·РјС–СЂСѓ С„Р°Р№Р»С–РІ С– РѕР±СЂР°Р·Сѓ ---
    ImageSize := fStream.Size;
    TConsole.WriteLn(Format('в†’ Total file data size: %.2f MB', [TotalFileSize / (1024 * 1024)]));
    TConsole.WriteLn(Format('в†’ Image file size: %.2f MB', [ImageSize / (1024 * 1024)]));

    if ImageSize > TotalFileSize * 2 then
      Errors.Add(Format('вљ  Image size (%.2f MB) is significantly larger than total file data (%.2f MB)',
        [ImageSize / (1024 * 1024), TotalFileSize / (1024 * 1024)]));
    // ------------------------------------------------------


    if Fix and (Errors.Count > 0) then
    begin
      TConsole.WriteLn('в†’ Changes applied (Fix=True), flushing changes...');
      fChanged := True;
      Flush;
    end;

    if Errors.Count = 0 then
      TConsole.WriteLn('вњ” Fsck finished: no errors found')
    else
      TConsole.WriteLn(Format('вљ  Fsck finished: %d errors/warnings found', [Errors.Count]));

  finally
    seenBlocks.Free;
    claimedBlocks.Free;
    {$IFDEF USEGENERICS}
    usedLinks.Free;
    {$ENDIF}
  end;
end;


end.
