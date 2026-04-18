unit uAutoloader;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, uMisc;

type
  TFileType = (ftUnknown, ftUser, ftOS, ftRadio, ftIFS);

type
  TPEAutoloaderFileInfo = record
    Offset: int64;
    Size: int64;
    FileType: TFileType;
    Index: integer;
  end;

  TPEAutoloaderFileInfoArray = array of TPEAutoloaderFileInfo;

function AnalyzePEAutoloaderFiles(SourceStream: TFileStream): TPEAutoloaderFileInfoArray;
function AnalyzePEAutoloaderFiles(const FileName: string): TPEAutoloaderFileInfoArray;
procedure ExtractBlackBerryAutoloaderFromPE(const fileName: string);

function MakeAutoloader(oFile: string; const iFiles: TStringList; capexe: string = 'cap.exe';
  ver: integer = 2; cb: TProgressCallback = nil): boolean;

function ExtractCap(inFile, outFile: string): boolean;


implementation

uses PEFile, Math, FileUtil;

function ReadFileCount(Stream: TStream): int64;
const
  MAX_OFFSET_SEARCH = 1000;  // або інше обмеження
var
  OffsetTablePos: int64;
  SearchAttempts: integer;
  PosBeforeSearch: int64;
begin
  Result := 0;
  SearchAttempts := 0;
  PosBeforeSearch := Stream.Position;

  repeat
    // Читаємо потенційний офсет таблиці
    if Stream.Read(OffsetTablePos, SizeOf(int64)) <> SizeOf(int64) then
      raise Exception.Create('Unexpected end of file while searching for offset table');

    // Перевіряємо валідність позиції офсета таблиці
    if (OffsetTablePos > PosBeforeSearch) and (OffsetTablePos < Stream.Size) and
      (Abs(OffsetTablePos - Stream.Position) < 1000) then
    begin
      // Повертаємось на 16 байт назад (логіка з вашого коду)
      Stream.Position := Stream.Position - 16;

      // Читаємо FileCount
      if Stream.Read(Result, SizeOf(int64)) <> SizeOf(int64) then
        raise Exception.Create('Error reading file count');

      Exit;
    end;

    Inc(SearchAttempts);
  until SearchAttempts >= MAX_OFFSET_SEARCH;

  raise Exception.Create('Failed to find valid file count after max search attempts');
end;

const
  START_SIGNATURE_DWORD = $97C5D59C; // little endian '…'
  PFCQ_SIGNATURE = $71636670; // 'pfcq' in little-endian

  SCAN_BLOCK_SIZE = 65536;
  MAX_FILES = 10;

function FindSignature(const Stream: TStream; StartPos: int64): int64;
var
  Buffer: array of byte;
  Position, I: int64;
  BytesRead, SearchSize: integer;
  DWordPtr1, DWordPtr2: PDWORD;
begin
  Result := -1;
  SetLength(Buffer, SCAN_BLOCK_SIZE);
  Position := StartPos;

  while Position < Stream.Size - 20 do
  begin
    Stream.Position := Position;
    BytesRead := Stream.Read(Buffer[0], Length(Buffer));
    if BytesRead < 20 then Break;

    SearchSize := BytesRead - 19;
    for I := 0 to SearchSize - 1 do
    begin
      DWordPtr1 := PDWORD(@Buffer[I]);
      DWordPtr2 := PDWORD(@Buffer[I + 8]);

      if (DWordPtr1^ = START_SIGNATURE_DWORD) and (DWordPtr2^ = START_SIGNATURE_DWORD) then
      begin
        Result := Position + I + 20;
        Exit;
      end;
    end;

    Position := Position + SearchSize;
  end;
end;

function DetermineFileType(const Buffer: array of byte): TFileType;
var
  I: integer;
  DWordPtr: PDWORD;
begin
  Result := ftUnknown;
  for I := 0 to Min(Length(Buffer), 64) - 16 do
  begin
    DWordPtr := PDWORD(@Buffer[I]);
    if DWordPtr^ = PFCQ_SIGNATURE then
    begin
      case Buffer[I + 12] of
        5: Result := ftUser;
        6: Result := ftOS;
        8: Result := ftIFS;
        12: Result := ftRadio;
      end;
      Break;
    end;
  end;
end;

function GetFileExtension(FileType: TFileType; Index: integer): string;
begin
  case FileType of
    ftUser: Result := Format('.%d@User.signed', [Index]);
    ftOS: Result := Format('.%d@OS.signed', [Index]);
    ftIFS: Result := Format('.%d@IFS.signed', [Index]);
    ftRadio: Result := Format('.%d@Radio.signed', [Index]);
    else
      Result := Format('.%d.signed', [Index]);
  end;
end;


function AnalyzePEAutoloaderFiles(SourceStream: TFileStream): TPEAutoloaderFileInfoArray;
var
  PeEndOffset, SignaturePos: int64;
  FileCount, I: int64;
  Offsets: array of int64;
  Buffer: array of byte;
begin
  PeEndOffset := GetPEEndOffset(SourceStream);
  if PeEndOffset = 0 then
    raise Exception.Create('Invalid or corrupted PE file');

  SignaturePos := FindSignature(SourceStream, PeEndOffset);
  if SignaturePos < 0 then
    raise Exception.Create('BlackBerry autoloader signature not found after PE data');

  SourceStream.Position := SignaturePos;

  // Зчитуємо FileCount, офсети
  FileCount := ReadFileCount(SourceStream);
  // функція, що читає коректно count (логіка з твого коду)
  if (FileCount < 1) or (FileCount > MAX_FILES) then
    raise Exception.CreateFmt('Invalid file count: %d (expected 1-%d)', [FileCount, MAX_FILES]);

  SetLength(Offsets, FileCount + 1);
  for I := 0 to FileCount - 1 do
  begin
    if SourceStream.Read(Offsets[I], SizeOf(int64)) <> SizeOf(int64) then
      raise Exception.Create('Error reading file offset');
    if (Offsets[I] < 0) or (Offsets[I] >= SourceStream.Size) then
      raise Exception.CreateFmt('Invalid file offset %d: %d', [I, Offsets[I]]);
  end;
  Offsets[FileCount] := SourceStream.Size;

  SetLength(Result, FileCount);

  for I := 0 to FileCount - 1 do
  begin
    Result[I].Offset := Offsets[I];
    Result[I].Size := Offsets[I + 1] - Offsets[I];
    Result[I].Index := I;

    // Читаємо перші байти для визначення типу
    SourceStream.Position := Offsets[I];
    SetLength(Buffer, Min(64, Result[I].Size));
    SourceStream.Read(Buffer[0], Length(Buffer));

    Result[I].FileType := DetermineFileType(Buffer);
  end;

end;

function AnalyzePEAutoloaderFiles(const FileName: string): TPEAutoloaderFileInfoArray;
var
  SourceStream: TFileStream;
begin
  SourceStream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    Result := AnalyzePEAutoloaderFiles(SourceStream);
  finally
    SourceStream.Free;
  end;
end;


procedure ExtractPEAutoloaderFiles(const FileName: string; const Files: TPEAutoloaderFileInfoArray);
var
  SourceStream: TFileStream;
  OutputFile: TFileStream;
  OutputFileName: string;
  I: integer;
begin
  if Length(Files) = 0 then Exit;

  SourceStream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    Writeln(Format('Extracting %d files from %s...', [Length(Files), ExtractFileName(FileName)]));

    for I := 0 to High(Files) do
    begin
      if Files[I].Size <= 0 then
      begin
        Writeln(Format('Skipping file %d: invalid size (%d)', [Files[I].Index, Files[I].Size]));
        Continue;
      end;

      SourceStream.Position := Files[I].Offset;
      OutputFileName := ChangeFileExt(FileName, GetFileExtension(Files[I].FileType, Files[I].Index));

      OutputFile := TFileStream.Create(OutputFileName, fmCreate);
      try
        CopyStreamData(SourceStream, OutputFile, Files[I].Size);
        Writeln(Format('Extracted: %s (%s bytes)', [ExtractFileName(OutputFileName),
          FormatFloat('#,##0', Files[I].Size)]));
      finally
        OutputFile.Free;
      end;
    end;

    Writeln('Extraction completed successfully.');
  finally
    SourceStream.Free;
  end;
end;


procedure ExtractBlackBerryAutoloaderFromPE(const FileName: string);
var
  files: TPEAutoloaderFileInfoArray;
begin
  files := AnalyzePEAutoloaderFiles(FileName);
  ExtractPEAutoloaderFiles(FileName, files);
end;


function GetCapSize(Stream: TStream): int64;
begin
  Result := GetPEEndOffset(Stream);
  if Result = 0 then exit;
  Result := FindSignature(Stream, Result) - 20;
  if Result < 0 then Result := Stream.Size;
end;

function ExtractCap(inFile, outFile: string): boolean;
var
  capSize: int64;
  outStream: TFileStream;
  cap: TFileStream;
begin
  cap := TFileStream.Create(inFile, fmOpenRead or fmShareDenyWrite);
  try
    capSize := GetCapSize(cap);
    if CapSize = cap.Size then Exit(False);
    cap.Position := 0;
    outStream := TFileStream.Create(outFile, fmCreate or fmShareExclusive);
    try
      outStream.CopyFrom(cap, capSize);
    finally
      FreeAndNil(outStream);
    end;
  finally
    FreeAndNil(cap);
  end;
  Result := True;
end;


function MakeAutoloader(oFile: string; const iFiles: TStringList; capexe: string = 'cap.exe';
  ver: integer = 2; cb: TProgressCallback = nil): boolean;
var
  inStream: TFileStream;
  outStream: TFileStream;
  cap: TFileStream;
  off, capSize, xDelta: int64;
  i, c: integer;
begin
  cap := TFileStream.Create(capexe, fmOpenRead or fmShareDenyWrite);
  try
    capSize := GetPEEndOffset(cap);
    cap.Position := 0;
    outStream := TFileStream.Create(oFile, fmCreate or fmShareExclusive);
    try
      outStream.CopyFrom(cap, capSize);
      outStream.WriteDWord(START_SIGNATURE_DWORD);
      outStream.WriteDWord(START_SIGNATURE_DWORD);
      outStream.WriteDWord(START_SIGNATURE_DWORD);

      xDelta := 52;
      if ver = 2 then
      begin
        Inc(xDelta, 80);
        for i := 0 to 19 do
          outStream.WriteDWord(0);

      end;

      c := iFiles.Count;
      outStream.WriteDWord(c);
      off := capSize + xDelta;
      for i := 0 to c - 1 do
      begin
        outStream.WriteDWord(0);
        outStream.WriteDWord(off);
        Inc(off, FileSize(iFiles.Strings[i]));
      end;
      while outStream.Position < capSize + xDelta do
        outStream.WriteDWord(0);

      for i := 0 to c - 1 do
      begin
        inStream := TFileStream.Create(iFiles.Strings[i], fmOpenReadWrite or fmShareDenyWrite);
        try
          outStream.CopyFrom(inStream, inStream.Size);
        finally
          FreeAndNil(inStream);
        end;
      end;
    finally
      FreeAndNil(outStream);
    end;
  finally
    FreeAndNil(cap);
  end;
  Result := True;
end;

end.
