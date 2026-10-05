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

  TPEAutoloaderHeaderInfo = record
    HeaderVersion: integer;   // 1 (legacy / 52B delta) або 2 (з 80B padding / 132B delta)
    SignaturePos: int64;    // Зміщення початку потрійної сигнатури
    OffsetTablePos: int64;  // Зміщення масиву offsets (відразу після FileCount)
    FileCount: integer;     // Кількість упакованих файлів
    Files: TPEAutoloaderFileInfoArray;
  end;

  TReplacementFile = record
    IsReplaced: boolean;
    NewStream: TStream;
    OwnsStream: boolean;
  end;

  { TAutoloaderFileStream }
  // Потік для безпосереднього читання вкладеного файла без збереження на диск
  TAutoloaderFileStream = class(TStream)
  private
    FSourceStream: TStream;
    FStartOffset: int64;
    FSize: int64;
    FPosition: int64;
    FOwnsStream: boolean;
  public
    constructor Create(SourceStream: TStream; AOffset, ASize: int64; AOwnsStream: boolean = False);
    destructor Destroy; override;
    function Read(var Buffer; Count: longint): longint; override;
    function Write(const Buffer; Count: longint): longint; override;
    function Seek(Offset: longint; Origin: word): longint; override;
    function Seek(const Offset: int64; Origin: TSeekOrigin): int64; override;
  end;

  { TAutoloaderReader }
  // Клас для роботи з автозавантажувачем (читання, вилучення, заміна, розширення)
  TAutoloaderReader = class
  private
    FStream: TFileStream;
    FHeaderInfo: TPEAutoloaderHeaderInfo;
    FFileName: string;
    FPendingRemovals: array of boolean;
    FReplacements: array of TReplacementFile;
    function GetPendingCount: integer;
    procedure ClearReplacements;
  public
    constructor Create(const AFileName: string);
    destructor Destroy; override;

    function OpenFileStream(Index: integer): TStream; overload;
    function OpenFileStream(FileType: TFileType): TStream; overload;

    procedure RemoveFile(Index: integer); overload;
    procedure RemoveFile(FileType: TFileType); overload;

    procedure ReplaceFile(Index: integer; NewStream: TStream; AOwnsStream: boolean = False); overload;
    procedure ReplaceFile(FileType: TFileType; NewStream: TStream; AOwnsStream: boolean = False); overload;
    procedure ReplaceFile(FileType: TFileType; const NewFileName: string); overload;

    function Pack(const OutFileName: string = ''): boolean;

    property HeaderInfo: TPEAutoloaderHeaderInfo read FHeaderInfo;
    property FileCount: integer read FHeaderInfo.FileCount;
    property Files: TPEAutoloaderFileInfoArray read FHeaderInfo.Files;
    property PendingRemovalsCount: integer read GetPendingCount;
    property FileName: string read FFileName;
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

function RebuildAutoloader(const OriginalPE, OutFile: string; const NewFiles: TStringList;
  cb: TProgressCallback = nil): boolean;

function ExtractCap(inFile, outFile: string): boolean;

implementation

uses PEFile, Math, FileUtil;

const
  START_SIGNATURE_DWORD = $97C5D59C;
  PFCQ_SIGNATURE = $71636670;
  SCAN_BLOCK_SIZE = 65536;
  MAX_FILES = 10;

  { TAutoloaderFileStream }

constructor TAutoloaderFileStream.Create(SourceStream: TStream; AOffset, ASize: int64; AOwnsStream: boolean);
begin
  inherited Create;
  FSourceStream := SourceStream;
  FStartOffset := AOffset;
  FSize := ASize;
  FPosition := 0;
  FOwnsStream := AOwnsStream;
end;

destructor TAutoloaderFileStream.Destroy;
begin
  if FOwnsStream then
    FreeAndNil(FSourceStream);
  inherited Destroy;
end;

function TAutoloaderFileStream.Read(var Buffer; Count: longint): longint;
var
  BytesToRead: int64;
begin
  if (FPosition < 0) or (FPosition >= FSize) then
    Exit(0);

  BytesToRead := Count;
  if FPosition + BytesToRead > FSize then
    BytesToRead := FSize - FPosition;

  FSourceStream.Position := FStartOffset + FPosition;
  Result := FSourceStream.Read(Buffer, BytesToRead);
  Inc(FPosition, Result);
end;

function TAutoloaderFileStream.Write(const Buffer; Count: longint): longint;
begin
  raise Exception.Create('TAutoloaderFileStream is read-only');
end;

function TAutoloaderFileStream.Seek(Offset: longint; Origin: word): longint;
begin
  Result := longint(Seek(int64(Offset), TSeekOrigin(Origin)));
end;

function TAutoloaderFileStream.Seek(const Offset: int64; Origin: TSeekOrigin): int64;
var
  NewPos: int64;
begin
  case Origin of
    soBeginning: NewPos := Offset;
    soCurrent: NewPos := FPosition + Offset;
    soEnd: NewPos := FSize + Offset;
    else
      NewPos := FPosition;
  end;

  if NewPos < 0 then NewPos := 0;
  if NewPos > FSize then NewPos := FSize;

  FPosition := NewPos;
  Result := FPosition;
end;

{ TAutoloaderReader }

constructor TAutoloaderReader.Create(const AFileName: string);
begin
  inherited Create;
  FFileName := AFileName;
  FStream := TFileStream.Create(FFileName, fmOpenReadWrite or fmShareDenyNone);
  try
    FHeaderInfo := AnalyzePEAutoloaderHeader(FStream);
    SetLength(FPendingRemovals, Length(FHeaderInfo.Files));
    SetLength(FReplacements, Length(FHeaderInfo.Files));
  except
    FreeAndNil(FStream);
    raise;
  end;
end;

destructor TAutoloaderReader.Destroy;
begin
  ClearReplacements;
  FreeAndNil(FStream);
  inherited Destroy;
end;

procedure TAutoloaderReader.ClearReplacements;
var
  I: integer;
begin
  for I := 0 to High(FReplacements) do
  begin
    if FReplacements[I].IsReplaced and FReplacements[I].OwnsStream then
      FreeAndNil(FReplacements[I].NewStream);
  end;
  SetLength(FReplacements, 0);
end;

function TAutoloaderReader.GetPendingCount: integer;
var
  I, C: integer;
begin
  C := 0;
  for I := 0 to High(FPendingRemovals) do
    if FPendingRemovals[I] then Inc(C);
  Result := C;
end;

function TAutoloaderReader.OpenFileStream(Index: integer): TStream;
begin
  if (Index < 0) or (Index >= Length(FHeaderInfo.Files)) then
    raise Exception.CreateFmt('Invalid file index: %d', [Index]);

  if FPendingRemovals[Index] then
    raise Exception.CreateFmt('File at index %d is marked for removal', [Index]);

  if FReplacements[Index].IsReplaced then
  begin
    FReplacements[Index].NewStream.Position := 0;
    Exit(FReplacements[Index].NewStream);
  end;

  Result := TAutoloaderFileStream.Create(FStream, FHeaderInfo.Files[Index].Offset,
    FHeaderInfo.Files[Index].Size, False);
end;

function TAutoloaderReader.OpenFileStream(FileType: TFileType): TStream;
var
  I: integer;
begin
  for I := 0 to High(FHeaderInfo.Files) do
  begin
    if (FHeaderInfo.Files[I].FileType = FileType) and not FPendingRemovals[I] then
      Exit(OpenFileStream(I));
  end;
  raise Exception.Create('File type not found or marked for removal');
end;

procedure TAutoloaderReader.RemoveFile(Index: integer);
begin
  if (Index < 0) or (Index >= Length(FHeaderInfo.Files)) then
    raise Exception.CreateFmt('Invalid file index: %d', [Index]);

  FPendingRemovals[Index] := True;
end;

procedure TAutoloaderReader.RemoveFile(FileType: TFileType);
var
  I: integer;
  Found: boolean;
begin
  Found := False;
  for I := 0 to High(FHeaderInfo.Files) do
  begin
    if FHeaderInfo.Files[I].FileType = FileType then
    begin
      FPendingRemovals[I] := True;
      Found := True;
    end;
  end;

  if not Found then
    raise Exception.Create('File type not found for removal');
end;

procedure TAutoloaderReader.ReplaceFile(Index: integer; NewStream: TStream; AOwnsStream: boolean);
begin
  if (Index < 0) or (Index >= Length(FHeaderInfo.Files)) then
    raise Exception.CreateFmt('Invalid file index: %d', [Index]);

  if FReplacements[Index].IsReplaced and FReplacements[Index].OwnsStream then
    FreeAndNil(FReplacements[Index].NewStream);

  FReplacements[Index].IsReplaced := True;
  FReplacements[Index].NewStream := NewStream;
  FReplacements[Index].OwnsStream := AOwnsStream;
  FPendingRemovals[Index] := False;
end;

procedure TAutoloaderReader.ReplaceFile(FileType: TFileType; NewStream: TStream; AOwnsStream: boolean);
var
  I: integer;
begin
  for I := 0 to High(FHeaderInfo.Files) do
  begin
    if FHeaderInfo.Files[I].FileType = FileType then
    begin
      ReplaceFile(I, NewStream, AOwnsStream);
      Exit;
    end;
  end;
  raise Exception.Create('File type not found for replacement');
end;

procedure TAutoloaderReader.ReplaceFile(FileType: TFileType; const NewFileName: string);
var
  FileStrm: TFileStream;
begin
  FileStrm := TFileStream.Create(NewFileName, fmOpenRead or fmShareDenyWrite);
  ReplaceFile(FileType, FileStrm, True);
end;

function TAutoloaderReader.Pack(const OutFileName: string): boolean;
var
  TargetFile, TempFile: string;
  OutStream: TFileStream;
  CurrentDataStream: TStream;
  NewCount, I, Idx: integer;
  FirstFileOffset, Off, CurrentTablePos, DataSize: int64;
  KeepIndexes: array of integer;
begin
  Result := False;

  NewCount := Length(FHeaderInfo.Files) - GetPendingCount;
  if NewCount <= 0 then
    raise Exception.Create('Cannot remove all files from autoloader');

  SetLength(KeepIndexes, NewCount);
  NewCount := 0;
  for I := 0 to High(FHeaderInfo.Files) do
  begin
    if not FPendingRemovals[I] then
    begin
      KeepIndexes[NewCount] := I;
      Inc(NewCount);
    end;
  end;

  if OutFileName <> '' then
    TargetFile := OutFileName
  else
    TargetFile := FFileName;

  TempFile := TargetFile + '.tmp';
  FirstFileOffset := FHeaderInfo.Files[0].Offset;

  OutStream := TFileStream.Create(TempFile, fmCreate or fmShareExclusive);
  try
    FStream.Position := 0;
    OutStream.CopyFrom(FStream, FHeaderInfo.OffsetTablePos - SizeOf(QWord));
    OutStream.WriteQWord(QWord(NewCount));

    Off := FirstFileOffset;
    for I := 0 to NewCount - 1 do
    begin
      Idx := KeepIndexes[I];
      OutStream.WriteQWord(Off);

      if FReplacements[Idx].IsReplaced then
        DataSize := FReplacements[Idx].NewStream.Size
      else
        DataSize := FHeaderInfo.Files[Idx].Size;

      Inc(Off, DataSize);
    end;

    CurrentTablePos := OutStream.Position;
    if CurrentTablePos > FirstFileOffset then
      raise Exception.Create('New offset table exceeds original header limits');

    while OutStream.Position < FirstFileOffset do
      OutStream.WriteDWord(0);

    for I := 0 to NewCount - 1 do
    begin
      Idx := KeepIndexes[I];
      if FReplacements[Idx].IsReplaced then
      begin
        CurrentDataStream := FReplacements[Idx].NewStream;
        CurrentDataStream.Position := 0;
        OutStream.CopyFrom(CurrentDataStream, CurrentDataStream.Size);
      end
      else
      begin
        CurrentDataStream := TAutoloaderFileStream.Create(FStream,
          FHeaderInfo.Files[Idx].Offset, FHeaderInfo.Files[Idx].Size, False);
        try
          OutStream.CopyFrom(CurrentDataStream, CurrentDataStream.Size);
        finally
          CurrentDataStream.Free;
        end;
      end;
    end;

  finally
    OutStream.Free;
  end;

  ClearReplacements;

  if TargetFile = FFileName then
  begin
    FreeAndNil(FStream);
    DeleteFile(FFileName);
    RenameFile(TempFile, FFileName);

    FStream := TFileStream.Create(FFileName, fmOpenReadWrite or fmShareDenyNone);
    FHeaderInfo := AnalyzePEAutoloaderHeader(FStream);
    SetLength(FPendingRemovals, Length(FHeaderInfo.Files));
    SetLength(FReplacements, Length(FHeaderInfo.Files));
  end
  else
  begin
    if FileExists(TargetFile) then DeleteFile(TargetFile);
    RenameFile(TempFile, TargetFile);
  end;

  Result := True;
end;

{ Helper Functions }

function ReadHeaderMetadata(Stream: TStream; var OutVersion: integer; var OutOffsetTablePos: int64): int64;
var
  FileCountVal: QWord;
  SigBasePos: int64;
begin
  Result := 0;
  OutVersion := 0;
  OutOffsetTablePos := -1;
  SigBasePos := Stream.Position - 12;

  if Stream.Read(FileCountVal, SizeOf(QWord)) = SizeOf(QWord) then
  begin
    if (FileCountVal >= 1) and (FileCountVal <= MAX_FILES) then
    begin
      OutVersion := 1;
      OutOffsetTablePos := Stream.Position;
      Result := FileCountVal;
      Exit;
    end;
  end;

  Stream.Position := SigBasePos + 12 + 80;
  if Stream.Read(FileCountVal, SizeOf(QWord)) = SizeOf(QWord) then
  begin
    if (FileCountVal >= 1) and (FileCountVal <= MAX_FILES) then
    begin
      OutVersion := 2;
      OutOffsetTablePos := Stream.Position;
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

  Result.SignaturePos := SignaturePos - 12;
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

  HdrInfo := AnalyzePEAutoloaderHeader(OriginalPE);
  if Length(HdrInfo.Files) = 0 then
    raise Exception.Create('Original autoloader contains no files to calculate data offset');

  FirstFileOffset := HdrInfo.Files[0].Offset;

  OrigStream := TFileStream.Create(OriginalPE, fmOpenRead or fmShareDenyNone);
  try
    OutStream := TFileStream.Create(OutFile, fmCreate or fmShareExclusive);
    try
      OutStream.CopyFrom(OrigStream, HdrInfo.OffsetTablePos - SizeOf(QWord));
      OutStream.WriteQWord(QWord(FileCount));

      Off := FirstFileOffset;
      for I := 0 to FileCount - 1 do
      begin
        Fn := NewFiles.Strings[I];
        if not FileExists(Fn) then
          raise Exception.CreateFmt('Input image file not found: %s', [Fn]);

        OutStream.WriteQWord(Off);
        Inc(Off, FileSize(Fn));
      end;

      CurrentTablePos := OutStream.Position;
      if CurrentTablePos > FirstFileOffset then
        raise Exception.Create('New file offset table exceeds original header boundaries');

      while OutStream.Position < FirstFileOffset do
        OutStream.WriteDWord(0);

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
