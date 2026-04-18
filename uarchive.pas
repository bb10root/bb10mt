unit uArchive;

{$mode ObjFPC}{$H+}
{$OPTIMIZATION ON}
{$INLINE ON}
interface

uses
  Classes, SysUtils;

const
  ARCHIVE_SIGNATURE = 'BB10MT';
  DEFAULT_BUFFER_SIZE = 65536; // 64KB buffer for better I/O performance
  CRC_BUFFER_SIZE = 32768;     // 32KB for CRC calculation

type
  TMyArcEntry = record
    Name: string;
    OrigSize: QWord;
    CompSize: QWord;
    DataOffset: QWord;
    CRC32: cardinal;
  end;
  PMyArcEntry = ^TMyArcEntry;

  // Simple hash map using TStringList for faster file lookups
  TEntryHashMap = class(TStringList)
  private
    function GetEntryPtr(const Key: string): PMyArcEntry;
  public
    constructor Create;
    destructor Destroy; override;
    procedure AddEntry(const Key: string; Entry: PMyArcEntry);
    property Items[const Key: string]: PMyArcEntry read GetEntryPtr; default;
  end;

  TMyArcReader = class
  private
    FStream: TStream;
    FOwnStream: boolean;
    FEntries: array of TMyArcEntry;
    FEntryMap: TEntryHashMap;
    FBufferStream: TMemoryStream; // Reusable buffer

    function ReadHeader: boolean;
    function FindEntry(const fileName: string; out entry: TMyArcEntry): boolean; inline;
    procedure BuildEntryMap;
  public
    constructor Create(aStream: TStream); overload;
    constructor Create(const ArchiveName: string); overload;
    destructor Destroy; override;

    function FileExists(const fileName: string): boolean; inline;
    function ExtractToBytes(const fileName: string; out Data: TBytes): boolean;
    function ExtractToStream(const fileName: string; DestStream: TStream): boolean;
    function GetFileList: TStringArray;
    function GetEntryCount: integer; inline;
    function GetEntry(Index: integer): TMyArcEntry; inline;
  end;

  TplLzmaOptions = record
    EOS: boolean;
    Algorithm: integer;
    NumBenchMarkPasses: integer;
    DictionarySize: integer;
    Lc: integer;
    Lp: integer;
    Pb: integer;
    Fb: integer;
    MatchFinder: integer;
  end;

  TMyArcWriter = class
  private
    FStream: TStream;
    FEntries: array of TMyArcEntry;
    FLzmaOptions: TplLzmaOptions;
    FHeaderSize: QWord;
    FBufferStream: TMemoryStream; // Reusable compression buffer

    procedure WriteHeaderPlaceholder;
    procedure UpdateHeader;
  public
    constructor Create(aStream: TStream);
    destructor Destroy; override;

    procedure SetLzmaOptions(const Options: TplLzmaOptions);
    procedure AddFile(const FileName: string);
    procedure AddFileFromStream(const EntryName: string; SourceStream: TStream);
    procedure Finalize; // Better name than SaveArchive

    // Helper to create default options
    class function DefaultLzmaOptions: TplLzmaOptions; static;
  end;

// Optimized compression/decompression functions
function CompressStreamLzma(InStream, OutStream: TStream; const AOptions: TplLzmaOptions): longint;
function DecompressStreamLzma(InStream, OutStream: TStream): int64;

// Shared utility functions
function ComputeStreamCRC32(Stream: TStream): cardinal;

implementation

uses
  ULZMAEncoder, ULZMACommon, ULZMADecoder, crc;

  {------------------------------}
  { TEntryHashMap }

constructor TEntryHashMap.Create;
begin
  inherited Create;
  Sorted := True;  // Enable binary search for O(log n) lookups
  Duplicates := dupError;
  CaseSensitive := False;
end;

destructor TEntryHashMap.Destroy;
var
  i: integer;
begin
  // Clean up all entry pointers
  for i := 0 to Count - 1 do
    if Assigned(Objects[i]) then
      Dispose(PMyArcEntry(Objects[i]));
  inherited Destroy;
end;

function TEntryHashMap.GetEntryPtr(const Key: string): PMyArcEntry;
var
  Index: integer;
begin
  if Find(Key, Index) then
    Result := PMyArcEntry(Objects[Index])
  else
    Result := nil;
end;

procedure TEntryHashMap.AddEntry(const Key: string; Entry: PMyArcEntry);
begin
  AddObject(Key, TObject(Entry));
end;

{------------------------------}
{ Shared Utility Functions }

function ComputeStreamCRC32(Stream: TStream): cardinal;
var
  Buffer: array[0..CRC_BUFFER_SIZE - 1] of byte;
  BytesRead: integer;
  crc: cardinal;
  SavePos: int64;
begin
  SavePos := Stream.Position;
  crc := crc32(0, nil, 0);
  Stream.Position := 0;

  repeat
    BytesRead := Stream.Read(Buffer, CRC_BUFFER_SIZE);
    if BytesRead > 0 then
      crc := crc32(crc, @Buffer[0], BytesRead);
  until BytesRead = 0;

  Stream.Position := SavePos;
  Result := crc;
end;

{------------------------------}
{ Optimized LZMA Functions }

function CompressStreamLzma(InStream, OutStream: TStream; const AOptions: TplLzmaOptions): longint;
var
  encoder: TLZMAEncoder;
  xfilesize: int64;
  i: integer;
  StartPos: int64;
begin
  Result := 0;
  if (InStream = nil) or (OutStream = nil) then Exit;

  StartPos := OutStream.Position;
  InStream.Position := 0;

  encoder := TLZMAEncoder.Create;
  try
    // Set encoder properties with error checking
    if not encoder.SetAlgorithm(AOptions.Algorithm) then
      raise Exception.CreateFmt('Invalid compression algorithm: %d', [AOptions.Algorithm]);

    if not encoder.SetDictionarySize(AOptions.DictionarySize) then
      raise Exception.CreateFmt('Invalid dictionary size: %d', [AOptions.DictionarySize]);

    if not encoder.SeNumFastBytes(AOptions.Fb) then
      raise Exception.CreateFmt('Invalid fast bytes value: %d', [AOptions.Fb]);

    if not encoder.SetMatchFinder(AOptions.MatchFinder) then
      raise Exception.CreateFmt('Invalid match finder: %d', [AOptions.MatchFinder]);

    if not encoder.SetLcLpPb(AOptions.Lc, AOptions.Lp, AOptions.Pb) then
      raise Exception.CreateFmt('Invalid Lc/Lp/Pb values: %d/%d/%d',
        [AOptions.Lc, AOptions.Lp, AOptions.Pb]);

    encoder.SetEndMarkerMode(AOptions.EOS);
    encoder.WriteCoderProperties(OutStream);

    // Write file size
    if AOptions.EOS then
      xfileSize := -1
    else
      xfileSize := InStream.Size;

    for i := 0 to 7 do
      OutStream.WriteByte(byte((xfileSize shr (8 * i)) and $FF));

    // Perform compression
    encoder.Code(InStream, OutStream, -1, -1);
    Result := OutStream.Position - StartPos;
  finally
    encoder.Free;
  end;
end;

function DecompressStreamLzma(InStream, OutStream: TStream): int64;
const
  PROPERTIES_SIZE = 5;
var
  decoder: TLZMADecoder;
  properties: array[0..PROPERTIES_SIZE - 1] of byte;
  i: integer;
  v: byte;
  outSize: int64;
begin
  Result := 0;
  if (InStream = nil) or (OutStream = nil) then Exit;

  InStream.Position := 0;

  if InStream.Read(properties, PROPERTIES_SIZE) <> PROPERTIES_SIZE then
    raise Exception.Create('Input stream too short - cannot read LZMA properties');

  decoder := TLZMADecoder.Create;
  try
    if not decoder.SetDecoderProperties(properties) then
      raise Exception.Create('Invalid LZMA stream properties');

    // Read uncompressed size
    outSize := 0;
    for i := 0 to 7 do
    begin
      if InStream.Read(v, 1) <> 1 then
        raise Exception.Create('Cannot read stream size from LZMA header');
      outSize := outSize or (int64(v) shl (8 * i));
    end;

    if not decoder.Code(InStream, OutStream, outSize) then
      raise Exception.Create('LZMA decompression failed');

    Result := outSize;
  finally
    decoder.Free;
  end;
end;

{------------------------------}
{ TMyArcReader }

constructor TMyArcReader.Create(const ArchiveName: string);
begin
  FOwnStream := True;
  FStream := TFileStream.Create(ArchiveName, fmOpenRead or fmShareDenyWrite);
  FEntryMap := TEntryHashMap.Create;
  FBufferStream := TMemoryStream.Create;

  if not ReadHeader then
    raise Exception.CreateFmt('Invalid archive format or corrupted header: %s', [ArchiveName]);
end;

constructor TMyArcReader.Create(aStream: TStream);
begin
  FOwnStream := False;
  FStream := aStream;
  FEntryMap := TEntryHashMap.Create;
  FBufferStream := TMemoryStream.Create;

  if not ReadHeader then
    raise Exception.Create('Invalid archive format or corrupted header');
end;

destructor TMyArcReader.Destroy;
begin
  // FEntryMap destructor will handle cleanup of entry pointers
  FreeAndNil(FEntryMap);
  FreeAndNil(FBufferStream);
  if FOwnStream then
    FreeAndNil(FStream);
  inherited Destroy;
end;

function TMyArcReader.ReadHeader: boolean;
var
  sig: array[0..Length(ARCHIVE_SIGNATURE) - 1] of char;
  Count, i: integer;
  nameLen: DWORD;
  Name: string;
  entry: TMyArcEntry;
begin
  Result := False;
  SetLength(FEntries, 0);

  try
    FStream.Position := 0;
    if FStream.Read(sig, Length(ARCHIVE_SIGNATURE)) <> Length(ARCHIVE_SIGNATURE) then
      Exit;

    if string(sig) <> ARCHIVE_SIGNATURE then
      Exit;

    if FStream.Read(Count, SizeOf(DWORD)) <> SizeOf(DWORD) then
      Exit;

    if (Count < 0) or (Count > 1000000) then // Sanity check
      Exit;

    SetLength(FEntries, Count);

    for i := 0 to Count - 1 do
    begin
      if FStream.Read(nameLen, SizeOf(DWORD)) <> SizeOf(DWORD) then
        Exit;

      if nameLen > 4096 then // Reasonable filename limit
        Exit;

      SetLength(Name, nameLen);
      if nameLen > 0 then
        if FStream.Read(Name[1], nameLen) <> nameLen then
          Exit;

      entry.Name := Name;

      if FStream.Read(entry.OrigSize, SizeOf(QWord)) <> SizeOf(QWord) then Exit;
      if FStream.Read(entry.CompSize, SizeOf(QWord)) <> SizeOf(QWord) then Exit;
      if FStream.Read(entry.DataOffset, SizeOf(QWord)) <> SizeOf(QWord) then Exit;
      if FStream.Read(entry.CRC32, SizeOf(cardinal)) <> SizeOf(cardinal) then Exit;

      FEntries[i] := entry;
    end;

    BuildEntryMap;
    Result := True;
  except
    Result := False;
  end;
end;

procedure TMyArcReader.BuildEntryMap;
var
  i: integer;
  EntryPtr: PMyArcEntry;
begin
  FEntryMap.Clear;
  for i := 0 to High(FEntries) do
  begin
    New(EntryPtr);
    EntryPtr^ := FEntries[i];
    FEntryMap.AddEntry(UpperCase(FEntries[i].Name), EntryPtr);
  end;
end;

function TMyArcReader.FindEntry(const fileName: string; out entry: TMyArcEntry): boolean;
var
  EntryPtr: PMyArcEntry;
begin
  EntryPtr := FEntryMap[UpperCase(fileName)];
  if Assigned(EntryPtr) then
  begin
    entry := EntryPtr^;
    Result := True;
  end
  else
    Result := False;
end;

function TMyArcReader.FileExists(const fileName: string): boolean;
begin
  Result := Assigned(FEntryMap[UpperCase(fileName)]);
end;

function TMyArcReader.GetFileList: TStringArray;
var
  i: integer;
begin
  SetLength(Result, Length(FEntries));
  for i := 0 to High(FEntries) do
    Result[i] := FEntries[i].Name;
end;

function TMyArcReader.GetEntryCount: integer;
begin
  Result := Length(FEntries);
end;

function TMyArcReader.GetEntry(Index: integer): TMyArcEntry;
begin
  if (Index >= 0) and (Index < Length(FEntries)) then
    Result := FEntries[Index]
  else
    raise Exception.CreateFmt('Entry index out of bounds: %d', [Index]);
end;

function TMyArcReader.ExtractToStream(const fileName: string; DestStream: TStream): boolean;
var
  entry: TMyArcEntry;
  crc: cardinal;
  SavePos: int64;
begin
  Result := False;
  if not FindEntry(fileName, entry) then Exit;

  SavePos := FStream.Position;
  try
    // Read compressed data
    FBufferStream.Clear;
    FStream.Position := entry.DataOffset;
    FBufferStream.CopyFrom(FStream, entry.CompSize);

    // Verify CRC32 of compressed data
    crc := ComputeStreamCRC32(FBufferStream);
    if crc <> entry.CRC32 then
      raise Exception.CreateFmt('CRC32 mismatch for file "%s": expected %x, got %x',
        [fileName, entry.CRC32, crc]);

    // Decompress
    FBufferStream.Position := 0;
    if DecompressStreamLzma(FBufferStream, DestStream) <> entry.OrigSize then
      raise Exception.CreateFmt('Decompression size mismatch for file "%s"', [fileName]);

    Result := True;
  finally
    FStream.Position := SavePos;
  end;
end;

function TMyArcReader.ExtractToBytes(const fileName: string; out Data: TBytes): boolean;
var
  ms: TMemoryStream;
begin
  ms := TMemoryStream.Create;
  try
    Result := ExtractToStream(fileName, ms);
    if Result then
    begin
      SetLength(Data, ms.Size);
      if ms.Size > 0 then
        Move(ms.Memory^, Data[0], ms.Size);
    end;
  finally
    ms.Free;
  end;
end;

{------------------------------}
{ TMyArcWriter }

constructor TMyArcWriter.Create(aStream: TStream);
begin
  FStream := aStream;
  SetLength(FEntries, 0);
  FBufferStream := TMemoryStream.Create;

  // Default LZMA options
  FLzmaOptions := DefaultLzmaOptions;

  WriteHeaderPlaceholder;
end;

destructor TMyArcWriter.Destroy;
begin
  FreeAndNil(FBufferStream);
  inherited Destroy;
end;

class function TMyArcWriter.DefaultLzmaOptions: TplLzmaOptions;
begin
  Result.EOS := False;
  Result.Algorithm := 2;
  Result.NumBenchMarkPasses := 10;
  Result.DictionarySize := 1 shl 23; // 8MB
  Result.Lc := 3;
  Result.Lp := 0;
  Result.Pb := 2;
  Result.Fb := 128;
  Result.MatchFinder := 1;
end;

procedure TMyArcWriter.SetLzmaOptions(const Options: TplLzmaOptions);
begin
  FLzmaOptions := Options;
end;

procedure TMyArcWriter.WriteHeaderPlaceholder;
var
  i: integer;
  zero: QWord;
begin
  FStream.Position := 0;
  FStream.WriteBuffer(ARCHIVE_SIGNATURE[1], Length(ARCHIVE_SIGNATURE));

  zero := 0;
  FStream.WriteBuffer(zero, SizeOf(DWORD)); // Entry count placeholder

  FHeaderSize := FStream.Position;
end;

procedure TMyArcWriter.AddFileFromStream(const EntryName: string; SourceStream: TStream);
var
  entry: TMyArcEntry;
  OriginalPos: int64;
begin
  OriginalPos := SourceStream.Position;
  try
    SourceStream.Position := 0;

    // Compress to buffer
    FBufferStream.Clear;
    CompressStreamLzma(SourceStream, FBufferStream, FLzmaOptions);

    // Create entry
    entry.Name := EntryName;
    entry.OrigSize := SourceStream.Size;
    entry.CompSize := FBufferStream.Size;
    entry.DataOffset := FStream.Position;
    entry.CRC32 := ComputeStreamCRC32(FBufferStream);

    // Write compressed data to archive
    FBufferStream.Position := 0;
    FStream.CopyFrom(FBufferStream, FBufferStream.Size);

    // Add to entries list
    SetLength(FEntries, Length(FEntries) + 1);
    FEntries[High(FEntries)] := entry;
  finally
    SourceStream.Position := OriginalPos;
  end;
end;

procedure TMyArcWriter.AddFile(const FileName: string);
var
  fs: TFileStream;
begin
  if not FileExists(FileName) then
    raise Exception.CreateFmt('File not found: %s', [FileName]);

  fs := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    AddFileFromStream(ExtractFileName(FileName), fs);
  finally
    fs.Free;
  end;
end;

procedure TMyArcWriter.UpdateHeader;
var
  i, nameLen, entryCount: integer;
  SavePos: int64;
begin
  SavePos := FStream.Position;

  // Write entry count
  FStream.Position := Length(ARCHIVE_SIGNATURE);
  entryCount := Length(FEntries);
  FStream.WriteBuffer(entryCount, SizeOf(DWORD));

  // Write entry table
  for i := 0 to High(FEntries) do
  begin
    nameLen := Length(FEntries[i].Name);
    FStream.WriteBuffer(nameLen, SizeOf(DWORD));
    if nameLen > 0 then
      FStream.WriteBuffer(FEntries[i].Name[1], nameLen);
    FStream.WriteBuffer(FEntries[i].OrigSize, SizeOf(QWord));
    FStream.WriteBuffer(FEntries[i].CompSize, SizeOf(QWord));
    FStream.WriteBuffer(FEntries[i].DataOffset, SizeOf(QWord));
    FStream.WriteBuffer(FEntries[i].CRC32, SizeOf(cardinal));
  end;

  FStream.Position := SavePos;
end;

procedure TMyArcWriter.Finalize;
begin
  UpdateHeader;
end;

end.
