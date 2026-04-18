unit rcfs;

{$mode ObjFPC}{$H+}
{$OPTIMIZATION ON}
{$INLINE ON}

interface

uses
  Classes, SysUtils, mormot.crypt.core;

type
  rcfs_hdr = packed record
    magic: array [0..3] of char;
    ver: dword;
    zone_id: array[0..7] of char;
    hash1: array [0..31] of byte;
    hash2: array [0..31] of byte;
    verify_size: dword;
    unc2: dword;
  end;

  rcfs_superblock = packed record
    uuid: TGuid;
    unk_0: array[0..15] of byte;
    magic: array[0..7] of char;
    unk_1: dword;
    unk_2: dword;
    image_size: dword;
    inodes_count: dword;
    inodes_off: dword;
    inodes_size: dword;
    names_off: dword;
    names_size: dword;
    data_off: dword;
    data_size: dword;
  end;

  rcfs_inode = packed record
    unk: word;
    hash: word;
    mode: word;
    emode: word;
    nameoffset: dword;
    offset: dword;
    size: dword;
    time: dword;
    uid: dword;
    gid: dword;
  end;

  verifier_hdr = packed record
    magic: array [0..3] of char;
    files_count: dword;
    links_count: dword;
  end;

  verifier_item = packed record
    inode: dword;
    unk0: dword;
    packed_size: dword;
    hash: array[0..31] of byte;
    attr: dword;
  end;

  TRCFSdir = array of rcfs_inode;

  // Hash map for fast inode lookup
  TInodeHashMap = record
    Keys: array of string;
    Values: array of dword;
    Count: integer;
  end;

  TRCFS = class
  private
    fStream: TStream;
    fInodes: dword;
    fSuperblock: rcfs_superblock;
    fVerifierInode: rcfs_inode;
    fVerData: array of verifier_item;
    fVerifierMap: TInodeHashMap;
    fStringCache: array of record
      Offset: dword;
      Value: string;
      end;
    fStringCacheCount: integer;

    // Reusable buffers to reduce allocations
    fWorkBuffer: array of byte;
    fDecompBuffer: array of byte;
    fTempBuffer: array of byte;
    fTempBufferX: array of byte;

    procedure Open;
    procedure InitializeBuffers;

    // Centralized compression functions
    function WriteStreamToFile(inStream: TStream; var inode: rcfs_inode; out hash: TSha256Digest): integer;

    function ReadFileData(inode: rcfs_inode): TBytes;

    function GetCachedString(off: dword): string;

    procedure AddStringToCache(off: dword; const Value: string);
    procedure BuildVerifierMap;
    function FastVerifierLookup(inode: dword): integer; inline;
    function GetPackedSize(inode: rcfs_inode): cardinal;
  public
    constructor Create(Stream: TStream);
    destructor Destroy; override;
    procedure CheckUnverified;
    function replaceFile(const dst, src: string): integer;
    function corruptFile(const dst: string): integer;
    function readString(off: dword): string;

    procedure ExtractFileToStream(const inode: rcfs_inode; var outStream: TStream);

    function inodeByOffset(off: dword): dword; inline;
    function getInodeByPath(const Path: string; var inode: rcfs_inode): dword;
    function update_verifier(inode, packed_size: dword; const hash: TSha256Digest): integer;
    function GetInode(idx: dword): rcfs_inode; inline;
    procedure SetInode(idx: dword; aValue: rcfs_inode);
    function chmod(const dst: string; mode: integer): integer;
    function chown(const dst: string; GID, UID: integer): integer;
    function ReadDir(off, size: dword; var DI: TRCFSdir): integer;
    procedure ExtractTree(const inode: rcfs_inode; const outPath: string);

    property InodesCount: dword read fInodes;
  end;

implementation

uses Math, uCrypto, uLZO2;

const
  LZO_CHUNK_SIZE = $4000;
  MAX_NAME_LEN = 1024;
  STRING_CACHE_SIZE = 5120000;

  _LZO = (1 shl 7);
  _UCL = (1 shl 7) or (1 shl 6);
  _GZ = (1 shl 6);


constructor TRCFS.Create(Stream: TStream);
begin
  fStream := Stream;
  fStringCacheCount := 0;
  SetLength(fStringCache, STRING_CACHE_SIZE);

  InitializeBuffers;
  Open;
  BuildVerifierMap;
end;

destructor TRCFS.Destroy;
begin
  // Cleanup buffers
  SetLength(fWorkBuffer, 0);
  SetLength(fDecompBuffer, 0);
  SetLength(fTempBuffer, 0);
  SetLength(fTempBufferX, 0);
  SetLength(fStringCache, 0);
  SetLength(fVerifierMap.Keys, 0);
  SetLength(fVerifierMap.Values, 0);
  inherited Destroy;
end;

procedure TRCFS.InitializeBuffers;
begin
  SetLength(fWorkBuffer, LZO1X_999_MEM_COMPRESS);
  SetLength(fDecompBuffer, LZO_CHUNK_SIZE * 2);
  SetLength(fTempBuffer, LZO_CHUNK_SIZE);
  SetLength(fTempBufferX, MAX_NAME_LEN);
end;

procedure TRCFS.BuildVerifierMap;
var
  i: integer;
begin
  fVerifierMap.Count := Length(fVerData);
  SetLength(fVerifierMap.Keys, fVerifierMap.Count);
  SetLength(fVerifierMap.Values, fVerifierMap.Count);

  for i := 0 to High(fVerData) do
  begin
    fVerifierMap.Keys[i] := IntToStr(fVerData[i].inode);
    fVerifierMap.Values[i] := i;
  end;
end;

function TRCFS.FastVerifierLookup(inode: dword): integer;
var
  key: string;
  i: integer;
begin
  Result := -1;
  key := IntToStr(inode);

  for i := 0 to fVerifierMap.Count - 1 do
  begin
    if fVerifierMap.Keys[i] = key then
    begin
      Result := fVerifierMap.Values[i];
      Exit;
    end;
  end;
end;

function TRCFS.GetCachedString(off: dword): string;
var
  i: integer;
begin
  // Check cache first
  for i := 0 to fStringCacheCount - 1 do
  begin
    if fStringCache[i].Offset = off then
    begin
      Result := fStringCache[i].Value;
      Exit;
    end;
  end;

  // Not in cache, read from stream
  Result := '';
  if fStringCacheCount < STRING_CACHE_SIZE then
  begin
    fStream.Position := off;
    if fStream.Size - fStream.Position >= MAX_NAME_LEN then
      fStream.ReadBuffer(fTempBufferX[0], MAX_NAME_LEN)
    else
      fStream.ReadBuffer(fTempBufferX[0], fStream.Size - fStream.Position);

    Result := PChar(@fTempBufferX[0]);
    AddStringToCache(off, Result);
  end
  else
  begin
    fStream.Position := off;
    fStream.ReadBuffer(fTempBufferX[0], Min(MAX_NAME_LEN, fStream.Size - fStream.Position));
    Result := PChar(@fTempBufferX[0]);
  end;
end;

procedure TRCFS.AddStringToCache(off: dword; const Value: string);
begin
  if fStringCacheCount < STRING_CACHE_SIZE then
  begin
    fStringCache[fStringCacheCount].Offset := off;
    fStringCache[fStringCacheCount].Value := Value;
    Inc(fStringCacheCount);
  end;
end;


function TRCFS.ReadFileData(inode: rcfs_inode): TBytes;
begin
  SetLength(Result, inode.size);
  if inode.size > 0 then
  begin
    fStream.Position := inode.offset;
    fStream.ReadBuffer(Result[0], inode.size);
  end;
end;

function TRCFS.WriteStreamToFile(inStream: TStream; var inode: rcfs_inode; out hash: TSha256Digest): integer;
var
  chunk_offsets: array of longword;
  chunk_buffer: array of byte;
  comp_buffer: array of byte;
  chunk_count: integer;
  read_now: integer;
  comp_size, opt_size: longword;
  pos_data: cardinal;
  tempStream: TMemoryStream;
  i, t: integer;
  packed_size, original_size: integer;
  max_chunks: integer;
begin
  Result := 0;
  inStream.Position := 0;
  original_size := inStream.Size;

  // Р‘СѓС„РµСЂРё РѕРґРёРЅ СЂР°Р·
  SetLength(chunk_buffer, LZO_CHUNK_SIZE);
  SetLength(comp_buffer, LZO_CHUNK_SIZE + LZO_CHUNK_SIZE div 16 + 64 + 3);

  max_chunks := 1 + (original_size + LZO_CHUNK_SIZE - 1) div LZO_CHUNK_SIZE;

  SetLength(chunk_offsets, max_chunks);

  tempStream := TMemoryStream.Create;
  try
    t := (QWord(inode.emode) shl $17) shr $1E;

    if t = 1 then
    begin
      // *** LZO СЂРµР¶РёРј ***
      chunk_count := 1;
      packed_size := GetPackedSize(inode);
      packed_size := (packed_size + 3) and not 3;  // РѕРєСЂСѓРіР»РµРЅРЅСЏ РґРѕ DWORD
      // Р РµР·РµСЂРІСѓС”РјРѕ РјС–СЃС†Рµ РїС–Рґ С‚Р°Р±Р»РёС†СЋ РѕС„СЃРµС‚С–РІ
      pos_data := max_chunks * 4;
      tempStream.Size := pos_data;
      tempStream.Position := pos_data;
      chunk_offsets[0] := pos_data;
      while inStream.Position < inStream.Size do
      begin
        read_now := inStream.Read(chunk_buffer[0], LZO_CHUNK_SIZE);
        if read_now <= 0 then Break;

        // РЎС‚РёСЃРєР°С”РјРѕ LZO
        comp_size := Length(comp_buffer);
        if lzo1x_999_compress(@chunk_buffer[0], read_now, @comp_buffer[0], comp_size,
          @fWorkBuffer[0]) <> 0 then
          Exit(-3);// РџРѕРјРёР»РєР° LZO

        // РћРїС‚РёРјС–Р·СѓС”РјРѕ
        opt_size := read_now;
        if lzo1x_optimize(@comp_buffer[0], comp_size, @chunk_buffer[0], opt_size,
          @fWorkBuffer[0]) <> 0 then
          Exit(-4); // РџРѕРјРёР»РєР° optimize

        // Р—Р°РїРёСЃСѓС”РјРѕ СЃС‚РёСЃРЅРµРЅРёР№ Р±Р»РѕРє
        //tempStream.Position := pos_data;
        tempStream.WriteBuffer(comp_buffer[0], comp_size);
        //Inc(pos_data, comp_size);

        // Р—Р°РїРёСЃСѓС”РјРѕ РѕС„СЃРµС‚ РїРѕС‚РѕС‡РЅРѕРіРѕ Р±Р»РѕРєСѓ
        chunk_offsets[chunk_count] := tempStream.Position;
        Inc(chunk_count);

      end;

      // РџРѕРІРµСЂС‚Р°С”РјРѕСЃСЏ С– Р·Р°РїРёСЃСѓС”РјРѕ С‚Р°Р±Р»РёС†СЋ РѕС„СЃРµС‚С–РІ
      tempStream.Position := 0;
      for i := 0 to chunk_count - 1 do
        tempStream.WriteDWord(chunk_offsets[i]);

      // РЈСЃС–РєР°РЅРЅСЏ Р·Р°Р№РІРѕРіРѕ СЂРµР·РµСЂРІСѓ
      // if tempStream.Size > pos_data then
      //   tempStream.Size := pos_data;

      // РџРµСЂРµРІС–СЂРєР° РІРёРіС–РґРЅРѕСЃС‚С– LZO
      if (tempStream.Size > packed_size) and (original_size > packed_size) then
      begin
        Exit(-1); // LZO РЅРµ РІРёРіС–РґРЅРёР№
      end;
    end
    else
    begin
      // RAW СЂРµР¶РёРј вЂ” РїСЂРѕСЃС‚Рѕ РєРѕРїС–СЋС”РјРѕ
      tempStream.CopyFrom(inStream, original_size);
      inode.emode := inode.emode and (not _LZO); // РІРёРјРёРєР°С”РјРѕ LZO
    end;

    // Р—Р°РїРёСЃ Сѓ fStream
    fStream.Position := inode.offset;
    tempStream.Position := 0;
    fStream.CopyFrom(tempStream, tempStream.Size);
    Result := tempStream.Size;
    hash := SHA256OfStream(tempStream);

    // РћРЅРѕРІР»СЋС”РјРѕ СЂРѕР·РјС–СЂ СЂРѕР·РїР°РєРѕРІР°РЅРѕРіРѕ С„Р°Р№Р»Сѓ
    inode.size := original_size;
  finally
    tempStream.Free;
  end;
end;


function TRCFS.replaceFile(const dst, src: string): integer;
var
  idx: dword;
  errCode, outSize: integer;
  inode: rcfs_inode;
  inFile: TFileStream;
  fs: integer;
  hash: TSha256Digest;
begin
  Result := -1;

  idx := getInodeByPath(dst, inode);
  if idx = 0 then Exit;

  inFile := TFileStream.Create(src, fmOpenRead);
  try
    fs := inFile.Size;
    if fs = 0 then
      inode.size := 0
    else
      fs := WriteStreamToFile(inFile, inode, hash);
  finally
    inFile.Free;
  end;
  // Update verifier
  Result := 0;
  if fs >= 0 then
  begin
    SetInode(idx, inode);
    //Result := update_verifier(idx, fs, hash);
  end;
end;

function TRCFS.GetPackedSize(inode: rcfs_inode): cardinal;
var
  start_offset, table_size, chunk_count, i, last_offset, t: integer;
begin
  fStream.Position := inode.offset;
  t := (QWord(inode.emode) shl $17) shr $1E;

  if t = 1 then
  begin
    start_offset := fStream.ReadDWord;
    table_size := start_offset - 4;

    if (table_size < 0) or (table_size mod 4 <> 0) then
      raise Exception.Create('Invalid chunk table size');

    chunk_count := (table_size div 4); // Р±РµР· РїРµСЂС€РѕРіРѕ
    last_offset := start_offset;

    for i := 1 to chunk_count do
      last_offset := fStream.ReadDWord;

    // СЃСѓРјР°СЂРЅРёР№ СЂРѕР·РјС–СЂ = С‚Р°Р±Р»РёС†СЏ + РІСЃС– Р±Р»РѕРєРё
    Result := last_offset;
  end
  else
    Result := inode.size;
end;

const
  { File types }
  S_IFMT = 61440; { type of file mask}
  S_IFIFO = 4096;  { named pipe (fifo)}
  S_IFCHR = 8192;  { character special}
  S_IFDIR = 16384; { directory }
  S_IFBLK = 24576; { block special}
  S_IFREG = 32768; { regular }
  S_IFLNK = 40960; { symbolic link }
  S_IFSOCK = 49152; { socket }
  S_ISUID = &4000;
  S_ISGID = &2000;
  S_ISVTX = &1000;

function TRCFS.corruptFile(const dst: string): integer;
var
  idx: dword;
  inode: rcfs_inode;
  b: byte;
  ms : TMemoryStream;
  hash : TSha256Digest;
begin
  Result := -1;
  idx := getInodeByPath(dst, inode);
  if (idx = 0) or (inode.size = 0) or ((inode.mode and S_IFDIR) = S_IFDIR) then Exit;
  ms := TMemoryStream.Create;
  try
    //ExtractFileToStream(inode, ms);
    ms.SetSize(inode.size);
    ms.Position :=0;
    Result := WriteStreamToFile(ms, inode, hash);
  finally
    FreeAndNil(ms);
  end;
end;


function TRCFS.chmod(const dst: string; mode: integer): integer;
var
  idx: dword;
  inode: rcfs_inode;
begin
  Result := -1;
  idx := getInodeByPath(dst, inode);
  if (idx = 0) then Exit;
  inode.mode := (inode.mode and not ($FFF)) or (mode and $FFF);
  setInode(idx, inode);
end;

function TRCFS.chown(const dst: string; GID, UID: integer): integer;
var
  idx: dword;
  inode: rcfs_inode;
begin
  Result := -1;
  idx := getInodeByPath(dst, inode);
  if (idx = 0) then Exit;
  inode.gid := gid;
  inode.uid := uid;
  setInode(idx, inode);
end;


function TRCFS.getInodeByPath(const Path: string; var inode: rcfs_inode): dword;
var
  pathParts: TStringArray;
  i, j, s: integer;
  aName: string;
  DI: TRCFSdir;
  found: boolean;
begin
  Result := 1; // Root inode

  if (Path = '') or (Path = '/') then
  begin
    inode := GetInode(1);
    Exit;
  end;

  pathParts := Path.Split(['/']);

  for i := 0 to High(pathParts) do
  begin
    if pathParts[i] = '' then Continue;

    inode := GetInode(Result);
    s := ReadDir(inode.offset, inode.size, DI);
    found := False;

    for j := 0 to High(DI) do
    begin
      aName := GetCachedString(DI[j].nameoffset);
      if aName = pathParts[i] then
      begin
        Result := inodeByOffset(inode.offset + j * SizeOf(rcfs_inode));
        inode := DI[j];
        found := True;
        Break;
      end;
    end;

    if not found then
    begin
      Result := 0;
      Exit;
    end;
  end;
end;

function TRCFS.update_verifier(inode, packed_size: dword; const hash: TSha256Digest): integer;
var
  j: integer;
begin
  Result := -1;
  j := FastVerifierLookup(inode);
  if j >= 0 then
  begin
    fVerData[j].packed_size := packed_size;
    Move(hash[0], fVerData[j].hash[0], SizeOf(TSha256Digest));
    fStream.Position := fVerifierInode.offset + SizeOf(verifier_hdr) + j * SizeOf(verifier_item);
    fStream.WriteBuffer(fVerData[j], SizeOf(verifier_item));
    Result := 0;
  end;
end;

function TRCFS.inodeByOffset(off: dword): dword;
begin
  Result := 1 + (off - fInodes) div SizeOf(rcfs_inode);
end;

function TRCFS.GetInode(idx: dword): rcfs_inode;
begin
  fStream.Position := fInodes + (idx - 1) * SizeOf(rcfs_inode);
  fStream.ReadBuffer(Result, SizeOf(rcfs_inode));
end;

procedure TRCFS.SetInode(idx: dword; aValue: rcfs_inode);
begin
  fStream.Position := fInodes + (idx - 1) * SizeOf(rcfs_inode);
  fStream.WriteBuffer(aValue, SizeOf(rcfs_inode));
end;

procedure TRCFS.Open;
var
  hdr: rcfs_hdr;
  i, c: dword;
  vhdr: verifier_hdr;
begin
  fStream.Position := 0;
  fStream.ReadBuffer(hdr, SizeOf(rcfs_hdr));

  //if CompareMem(@hdr.magic[0], @'rimh'[1], 4) then
  //begin
  fStream.Position := $1000;
  fStream.ReadBuffer(fSuperblock, SizeOf(rcfs_superblock));

  if CompareMem(@fSuperblock.magic[0], @'r-c-f-s'[1], 8) then
  begin
    fInodes := fSuperblock.inodes_off;
    i := getInodeByPath('/verifier.log', fVerifierInode);

    if i > 0 then
    begin
      fStream.Position := fVerifierInode.offset;
      fStream.ReadBuffer(vhdr, SizeOf(verifier_hdr));

      if CompareMem(@vhdr.magic[0], @'VSIG'[1], 4) then
      begin
        c := vhdr.files_count + vhdr.links_count;
        SetLength(fVerData, c);
        if c > 0 then
          fStream.ReadBuffer(fVerData[0], c * SizeOf(verifier_item));
      end;
    end;
  end;
  //~end;
end;

function TRCFS.readString(off: dword): string;
begin
  fStream.Position := off;
  fStream.ReadBuffer(fTempBufferX[0], Min(MAX_NAME_LEN, fStream.Size - fStream.Position));
  Result := PChar(@fTempBufferX[0]);
end;

procedure TRCFS.CheckUnverified;

  procedure processDir(const inode: rcfs_inode; const cur_path: string);
  var
    i, j, k: integer;
    x, o, t: dword;
    DI: TRCFSdir;
    ct, aName: string;
  begin
    if (inode.offset = 0) or (inode.size = 0) then Exit;

    ReadDir(inode.offset, inode.size, DI);

    for i := 0 to High(DI) do
    begin
      aName := GetCachedString(DI[i].nameoffset);

      if (DI[i].mode and 16384) = 16384 then
        processDir(DI[i], cur_path + DirectorySeparator + aName)
      else
      begin
        k := inodeByOffset(inode.offset) + i;
        j := FastVerifierLookup(k);

        t := (QWord(DI[i].emode) shl $17) shr $1E;
        if t <> 0 then
        begin
          case t of
            1: ct := 'LZO';
            2: ct := 'UCL';
            else
              ct := 'UNK' + IntToStr(t);
          end;

          fStream.Position := DI[i].offset;
          o := fStream.ReadDWord;

          if o <> 8 then
          begin
            Write('[!]', ct, ' ', o, ':', cur_path + DirectorySeparator + aName);
            Dec(o, 4);
            while o > 0 do
            begin
              Dec(o, 4);
              x := fStream.ReadDWord;
              Write(x, ',');
            end;
            WriteLn;
          end;
        end;

        if j < 0 then
          WriteLn(cur_path + DirectorySeparator + aName);
      end;
    end;
  end;

begin
  WriteLn('Unverified files:');
  processDir(GetInode(1), '');
end;

function TRCFS.ReadDir(off, size: dword; var DI: TRCFSdir): integer;
begin
  Result := size div SizeOf(rcfs_inode);
  SetLength(DI, Result);
  if Result > 0 then
  begin
    fStream.Position := off;
    fStream.ReadBuffer(DI[0], size);
  end;
end;

procedure TRCFS.ExtractFileToStream(const inode: rcfs_inode; var outStream: TStream);
var
  i, chunk_count: integer;
  chunk_start, chunk_end, chunk_size: cardinal;
  decompressed_size: cardinal;
  offsets: array of cardinal;
  first_offset, tmp_offset: cardinal;
  t: integer;
begin
  fStream.Position := inode.offset;
  SetLength(fDecompBuffer, LZO_CHUNK_SIZE * 2);
  t := (QWord(inode.emode) shl $17) shr $1E;

  if t = 1 then
  begin
    // ---- 1. Р§РёС‚Р°С”РјРѕ С‚Р°Р±Р»РёС†СЋ РѕС„СЃРµС‚С–РІ ----
    first_offset := fStream.ReadDWord;
    SetLength(offsets, 1);
    offsets[0] := first_offset;
    chunk_count := 1;

    // Р§РёС‚Р°С”РјРѕ С–РЅС€С– РѕС„СЃРµС‚Рё РїРѕРєРё РЅРµ РґС–Р№РґРµРјРѕ РґРѕ РїРѕС‡Р°С‚РєСѓ РїРµСЂС€РѕРіРѕ С‡Р°РЅРєСѓ
    while fStream.Position < inode.offset + first_offset do
    begin
      tmp_offset := fStream.ReadDWord;
      SetLength(offsets, chunk_count + 1);
      offsets[chunk_count] := tmp_offset;
      Inc(chunk_count);
    end;

    // ---- 2. Р РѕР·РїР°РєРѕРІСѓС”РјРѕ С‡Р°РЅРєРё ----
    for i := 0 to High(offsets) - 1 do
    begin
      chunk_start := offsets[i];
      chunk_end := offsets[i + 1];
      chunk_size := chunk_end - chunk_start;

      if chunk_size <= 0 then
        raise Exception.CreateFmt('Invalid chunk size at %d', [i]);

      SetLength(fTempBuffer, chunk_size);
      fStream.Position := inode.offset + chunk_start;
      fStream.ReadBuffer(fTempBuffer[0], chunk_size);

      decompressed_size := 0;
      if lzo1x_decompress_safe(@fTempBuffer[0], chunk_size, @fDecompBuffer[0],
        decompressed_size, nil) <> 0 then
        raise Exception.CreateFmt('Decompress failed at chunk %d', [i]);

      outStream.WriteBuffer(fDecompBuffer[0], decompressed_size);
    end;
  end
  else
    outStream.CopyFrom(fStream, inode.size);

  SetLength(fDecompBuffer, 0);
end;


procedure TRCFS.ExtractTree(const inode: rcfs_inode; const outPath: string);
var
  DI: TRCFSdir;
  xPath, Name: string;
  fOut: TStream;
  i, k: integer;
begin
  Name := ReadString(inode.nameoffset);
  if Name <> '' then
    xPath := outPath + PathDelim + Name
  else
    xPath := outPath;
  WriteLn(Format('%.4X %.4X %s', [inode.mode, inode.emode, xPath]));
  if (inode.mode and S_IFDIR) = S_IFDIR then
  begin
    k := ReadDir(inode.offset, inode.size, DI);
    if not DirectoryExists(xPath) then
      MkDir(xPath);
    for i := 0 to k - 1 do
      ExtractTree(DI[i], xPath);
    SetLength(DI, 0);
  end
  else if (inode.mode and S_IFREG) = S_IFREG then
  begin
    fOut := TFileStream.Create(xPath, fmCreate);

    try
      if inode.size > 0 then
        ExtractFileToStream(inode, fOut);
    finally
      FreeAndNil(fOut);
    end;

  end;
  chmod(xPath, inode.mode);
  chown(xPath, inode.gid, inode.uid);

end;

initialization
  Assert(SizeOf(verifier_item) = $30, 'Wrong verifier_item size!');

end.
