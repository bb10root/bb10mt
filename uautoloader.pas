unit uAutoloader;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, uMisc;

type
  TFileType = (ftUnknown, ftUser, ftOS, ftRadio, ftIFS);

  TPEAutoloaderFileInfo = record
    Offset: int64;
    Size: int64;
    FileType: TFileType;
    Index: integer;
  end;

  TPEAutoloaderFileInfoArray = array of TPEAutoloaderFileInfo;

  // Структура для зберігання метаінформації про заголовок
  TPEAutoloaderHeaderInfo = record
    HeaderVersion: integer;   // 1 (legacy / 52B delta) або 2 ( з 80B padding / 132B delta)
    SignaturePos: int64;    // Зміщення початку потрійної сигнатури
    OffsetTablePos: int64;  // Зміщення масиву offsets (відразу після FileCount)
    FileCount: integer;     // Кількість упакованих файлів
    Files: TPEAutoloaderFileInfoArray;
  end;

function AnalyzePEAutoloaderHeader(SourceStream: TFileStream): TPEAutoloaderHeaderInfo; overload;
function AnalyzePEAutoloaderHeader(const FileName: string): TPEAutoloaderHeaderInfo; overload;

function AnalyzePEAutoloaderFiles(SourceStream: TFileStream): TPEAutoloaderFileInfoArray; overload;
function AnalyzePEAutoloaderFiles(const FileName: string): TPEAutoloaderFileInfoArray; overload;

procedure ExtractBlackBerryAutoloaderFromPE(const FileName: string; const OutDir: string = '');
procedure ExtractPEAutoloaderFiles(const FileName: string; const Files: TPEAutoloaderFileInfoArray;
  const OutDir: string = '');

function MakeAutoloader(oFile: string; const iFiles: TStringList; capexe: string = 'cap.exe';
  ver: integer = 2; cb: TProgressCallback = nil): boolean;

// Створює новий автозавантажувач на основі оригінального PE-файлу та його HdrInfo
function RebuildAutoloader(const OriginalPE, OutFile: string; const NewFiles: TStringList;
  cb: TProgressCallback = nil): boolean;

function ExtractCap(inFile, outFile: string): boolean;

implementation

uses PEFile, Math, FileUtil;

const
  START_SIGNATURE_DWORD = $97C5D59C; // Little endian signature
  PFCQ_SIGNATURE = $71636670; // 'pfcq'
  SCAN_BLOCK_SIZE = 65536;
  MAX_FILES = 10;

// Функція зчитує кількість файлів, повертаючи версію заголовка та позицію таблиці зміщень
function ReadHeaderMetadata(Stream: TStream; var OutVersion: integer; var OutOffsetTablePos: int64): int64;
var
  FileCountVal: QWord;
  SigBasePos: int64;
begin
  Result := 0;
  OutVersion := 0;
  OutOffsetTablePos := -1;

  // SigBasePos — це позиція ПОЧАТКУ сигнатури (SigPos - 12)
  SigBasePos := Stream.Position - 12;

  // Спроба 1: Читання для Версії 1 (відразу після 12-байтної сигнатури)
  if Stream.Read(FileCountVal, SizeOf(QWord)) = SizeOf(QWord) then
  begin
    if (FileCountVal >= 1) and (FileCountVal <= MAX_FILES) then
    begin
      OutVersion := 1;
      OutOffsetTablePos := Stream.Position; // Зміщення першого 64-бітного offset
      Result := FileCountVal;
      Exit;
    end;
  end;

  // Спроба 2: Читання для Версії 2 (зсув +80 байт нулів після сигнатури)
  Stream.Position := SigBasePos + 12 + 80;
  if Stream.Read(FileCountVal, SizeOf(QWord)) = SizeOf(QWord) then
  begin
    if (FileCountVal >= 1) and (FileCountVal <= MAX_FILES) then
    begin
      OutVersion := 2;
      OutOffsetTablePos := Stream.Position; // Зміщення першого 64-бітного offset
      Result := FileCountVal;
      Exit;
    end;
  end;

  raise Exception.Create('Failed to find valid file count or header version in autoloader');
end;

function FindSignature(const Stream: TStream; StartPos: int64): int64;
const
  SIG_DWORD = START_SIGNATURE_DWORD;
var
  Buffer: TBytes;
  Position, I: int64;
  BytesRead, SearchLimit: integer;
  P: pbyte;
begin
  Result := -1;
  SetLength(Buffer, SCAN_BLOCK_SIZE);
  Position := StartPos;

  while Position <= Stream.Size - 12 do
  begin
    Stream.Position := Position;
    BytesRead := Stream.Read(Buffer[0], Length(Buffer));
    if BytesRead < 12 then Break;

    SearchLimit := BytesRead - 12;
    I := 0;

    while I <= SearchLimit do
    begin
      P := @Buffer[I];
      if PDWord(P + 8)^ = SIG_DWORD then
      begin
        if (PDWord(P)^ = SIG_DWORD) and (PDWord(P + 4)^ = SIG_DWORD) then
        begin
          Result := Position + I + 12;
          // Повертає вказівник ВІДРАЗУ після 12 байт сигнатури
          Exit;
        end;
        Inc(I, 4);
      end
      else
        Inc(I, 4);
    end;

    Position := Position + SearchLimit;
  end;
end;

function DetermineFileType(const Buffer: array of byte): TFileType;
var
  I, MaxLen: integer;
  DWordPtr: PDWORD;
begin
  Result := ftUnknown;
  MaxLen := Min(Length(Buffer), 64);
  if MaxLen < 16 then Exit;

  for I := 0 to MaxLen - 16 do
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

function AnalyzePEAutoloaderHeader(SourceStream: TFileStream): TPEAutoloaderHeaderInfo;
var
  PeEndOffset, SignaturePos: int64;
  FileCount, I: int64;
  Offsets: array of int64;
  Buffer: TBytes;
begin
  PeEndOffset := GetPEEndOffset(SourceStream);
  if PeEndOffset = 0 then
    raise Exception.Create('Invalid or corrupted PE file');

  SignaturePos := FindSignature(SourceStream, PeEndOffset);
  if SignaturePos < 0 then
    raise Exception.Create('BlackBerry autoloader signature not found after PE data');

  Result.SignaturePos := SignaturePos - 12; // Точна позиція початку сигнатури
  SourceStream.Position := SignaturePos;

  FileCount := ReadHeaderMetadata(SourceStream, Result.HeaderVersion, Result.OffsetTablePos);
  Result.FileCount := FileCount;

  SetLength(Offsets, FileCount + 1);
  for I := 0 to FileCount - 1 do
  begin
    if SourceStream.Read(Offsets[I], SizeOf(int64)) <> SizeOf(int64) then
      raise Exception.Create('Error reading file offset');
    if (Offsets[I] < 0) or (Offsets[I] >= SourceStream.Size) then
      raise Exception.CreateFmt('Invalid file offset %d: %d', [I, Offsets[I]]);
  end;
  Offsets[FileCount] := SourceStream.Size;

  SetLength(Result.Files, FileCount);

  for I := 0 to FileCount - 1 do
  begin
    Result.Files[I].Offset := Offsets[I];
    Result.Files[I].Size := Offsets[I + 1] - Offsets[I];
    Result.Files[I].Index := I;

    SourceStream.Position := Offsets[I];
    SetLength(Buffer, Min(64, Result.Files[I].Size));
    if Length(Buffer) > 0 then
      SourceStream.ReadBuffer(Buffer[0], Length(Buffer));

    Result.Files[I].FileType := DetermineFileType(Buffer);
  end;
end;

function AnalyzePEAutoloaderHeader(const FileName: string): TPEAutoloaderHeaderInfo;
var
  SourceStream: TFileStream;
begin
  SourceStream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    Result := AnalyzePEAutoloaderHeader(SourceStream);
  finally
    SourceStream.Free;
  end;
end;

function AnalyzePEAutoloaderFiles(SourceStream: TFileStream): TPEAutoloaderFileInfoArray;
begin
  Result := AnalyzePEAutoloaderHeader(SourceStream).Files;
end;

function AnalyzePEAutoloaderFiles(const FileName: string): TPEAutoloaderFileInfoArray;
begin
  Result := AnalyzePEAutoloaderHeader(FileName).Files;
end;

procedure ExtractPEAutoloaderFiles(const FileName: string; const Files: TPEAutoloaderFileInfoArray;
  const OutDir: string = '');
var
  SourceStream, OutputFile: TFileStream;
  BaseFileName, TargetDir, OutputFileName: string;
  I: integer;
begin
  if Length(Files) = 0 then Exit;

  if OutDir <> '' then
  begin
    TargetDir := IncludeTrailingPathDelimiter(OutDir);
    if not DirectoryExists(TargetDir) then
      ForceDirectories(TargetDir);
  end
  else
    TargetDir := ExtractFilePath(FileName);

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

      BaseFileName := ExtractFileName(ChangeFileExt(FileName,
        GetFileExtension(Files[I].FileType, Files[I].Index)));
      OutputFileName := TargetDir + BaseFileName;

      OutputFile := TFileStream.Create(OutputFileName, fmCreate);
      try
        OutputFile.CopyFrom(SourceStream, Files[I].Size);
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

procedure ExtractBlackBerryAutoloaderFromPE(const FileName: string; const OutDir: string = '');
var
  hdr: TPEAutoloaderHeaderInfo;
begin
  hdr := AnalyzePEAutoloaderHeader(FileName);
  ExtractPEAutoloaderFiles(FileName, hdr.Files, OutDir);
end;

function GetCapSize(Stream: TStream): int64;
var
  PeEnd, SigPos: int64;
begin
  Result := Stream.Size;
  PeEnd := GetPEEndOffset(Stream);
  if PeEnd = 0 then Exit;

  SigPos := FindSignature(Stream, PeEnd);
  if SigPos >= 12 then
    Result := SigPos - 12;
end;

function ExtractCap(inFile, outFile: string): boolean;
var
  capSize: int64;
  outStream, cap: TFileStream;
begin
  Result := False;
  cap := TFileStream.Create(inFile, fmOpenRead or fmShareDenyWrite);
  try
    capSize := GetCapSize(cap);
    if capSize >= cap.Size then Exit;

    cap.Position := 0;
    outStream := TFileStream.Create(outFile, fmCreate or fmShareExclusive);
    try
      outStream.CopyFrom(cap, capSize);
      Result := True;
    finally
      outStream.Free;
    end;
  finally
    cap.Free;
  end;
end;

function MakeAutoloader(oFile: string; const iFiles: TStringList; capexe: string = 'cap.exe';
  ver: integer = 2; cb: TProgressCallback = nil): boolean;
var
  inStream, outStream, cap: TFileStream;
  off, capSize, xDelta: int64;
  i, c: integer;
  fn: string;
begin
  Result := False;
  if not FileExists(capexe) then
    raise Exception.CreateFmt('Base stub binary not found: %s', [capexe]);

  cap := TFileStream.Create(capexe, fmOpenRead or fmShareDenyWrite);
  try
    capSize := GetPEEndOffset(cap);
    if capSize = 0 then capSize := cap.Size;

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
      outStream.WriteQWord(c);

      off := capSize + xDelta;
      for i := 0 to c - 1 do
      begin
        fn := iFiles.Strings[i];
        if not FileExists(fn) then
          raise Exception.CreateFmt('Input image file not found: %s', [fn]);

        outStream.WriteQWord(off);
        Inc(off, FileSize(fn));
      end;

      while outStream.Position < capSize + xDelta do
        outStream.WriteDWord(0);

      for i := 0 to c - 1 do
      begin
        fn := iFiles.Strings[i];
        inStream := TFileStream.Create(fn, fmOpenRead or fmShareDenyWrite);
        try
          if Assigned(cb) then cb(fn, i, c);
          outStream.CopyFrom(inStream, inStream.Size);
        finally
          inStream.Free;
        end;
      end;

      if Assigned(cb) then cb(oFile, c, c);
      Result := True;
    finally
      outStream.Free;
    end;
  finally
    cap.Free;
  end;
end;

function RebuildAutoloader(const OriginalPE, OutFile: string; const NewFiles: TStringList;
  cb: TProgressCallback = nil): boolean;
var
  OrigStream, OutStream, InStream: TFileStream;
  HdrInfo: TPEAutoloaderHeaderInfo;
  FirstFileOffset, Off, CurrentTablePos: int64;
  FileCount, I: integer;
  Fn: string;
begin
  Result := False;

  if not FileExists(OriginalPE) then
    raise Exception.CreateFmt('Original autoloader binary not found: %s', [OriginalPE]);

  FileCount := NewFiles.Count;
  if (FileCount < 1) or (FileCount > MAX_FILES) then
    raise Exception.CreateFmt('Invalid file count for new autoloader: %d (max %d)', [FileCount, MAX_FILES]);

  // 1. Отримуємо точну метаінформацію оригінального автозавантажувача
  HdrInfo := AnalyzePEAutoloaderHeader(OriginalPE);
  if Length(HdrInfo.Files) = 0 then
    raise Exception.Create('Original autoloader contains no files to calculate data offset');

  // Використовуємо точний оригінальний офсет першого файлу як точку початку даних
  FirstFileOffset := HdrInfo.Files[0].Offset;

  OrigStream := TFileStream.Create(OriginalPE, fmOpenRead or fmShareDenyNone);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate or fmShareExclusive);
    try
      // 2. Копіюємо заголовок до лічильника файлів включно (HdrInfo.OffsetTablePos - SizeOf(QWord))
      OutStream.CopyFrom(OrigStream, HdrInfo.OffsetTablePos - SizeOf(QWord));

      // 3. Записуємо нову кількість файлів
      OutStream.WriteQWord(QWord(FileCount));

      // 4. Формуємо та записуємо нову таблицю зміщень
      Off := FirstFileOffset;
      for I := 0 to FileCount - 1 do
      begin
        Fn := NewFiles.Strings[I];
        if not FileExists(Fn) then
          raise Exception.CreateFmt('Input image file not found: %s', [Fn]);

        OutStream.WriteQWord(Off);
        Inc(Off, FileSize(Fn));
      end;

      // 5. Забиваємо нулями увесь залишковий простір до початку даних (FirstFileOffset)
      CurrentTablePos := OutStream.Position;
      if CurrentTablePos > FirstFileOffset then
        raise Exception.Create('New file offset table exceeds original header boundaries');

      while OutStream.Position < FirstFileOffset do
        OutStream.WriteDWord(0);

      // 6. Записуємо вміст нових образів
      for I := 0 to FileCount - 1 do
      begin
        Fn := NewFiles.Strings[I];
        InStream := TFileStream.Create(Fn, fmOpenRead or fmShareDenyWrite);
        try
          if Assigned(cb) then cb(Fn, I, FileCount);
          OutStream.CopyFrom(InStream, InStream.Size);
        finally
          InStream.Free;
        end;
      end;

      if Assigned(cb) then cb(OutFile, FileCount, FileCount);
      Result := True;
    finally
      OutStream.Free;
    end;
  finally
    OrigStream.Free;
  end;
end;

end.
