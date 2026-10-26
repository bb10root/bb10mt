unit bbflasher;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Math, bbconst, bbLoader;

type
  TBBFlasher = class
  private
    fLoader: TBBLoader;
    fDummySignature: array[0..559] of byte;
  public
    constructor Create(aLoader: TBBLoader);
    function FlashStream(aStream: TStream; ModelID: cardinal;
      AutoFreeStream: boolean = False): integer;
    function FlashFile(const fName: string; ModelID: cardinal; ver: byte = 2): integer;
  end;

implementation

uses uAutoloader, RIMSignatureParser, qcfm, CLI.Interfaces, CLI.Progress, CLI.Console;

constructor TBBFlasher.Create(aLoader: TBBLoader);
begin
  inherited Create;
  fLoader := aLoader;
  Move(signature_data[0], fDummySignature[0], SizeOf(fDummySignature));
end;

function TBBFlasher.FlashFile(const fName: string; ModelID: cardinal;
  ver: byte = 2): integer;
const
  MAGIC_MFCQ = $7163666D; // Magic 'mfcq'
var
  FileStream: TFileStream;
  aStream: TStream;
  ext: string;
  MagicVal: longword;
  isMFCQ, isEXE: boolean;
  AutoLoader: TAutoloaderReader;
  i: integer;
  iFiles: TStringList;
begin
  if not FileExists(fName) then
  begin
    TConsole.WriteLn('File not found: ' + fName, ccRed);
    Exit(-1);
  end;

  FileStream := TFileStream.Create(fName, fmOpenRead or fmShareDenyNone);
  try
    isMFCQ := False;
    isEXE := False;

    if (FileStream.Size >= SizeOf(MagicVal)) and
      (FileStream.Read(MagicVal, SizeOf(MagicVal)) = SizeOf(MagicVal)) then
    begin
      isMFCQ := (MagicVal = MAGIC_MFCQ);
      isEXE := ((MagicVal and $FFFF) = $5A4D) or ((MagicVal and $FFFF) = $4D5A);
    end;

    FileStream.Position := 0;

    if isEXE then
    begin
      AutoLoader := TAutoloaderReader.Create(fName);
      try
        Result := 0;
        for i := 0 to AutoLoader.FileCount - 1 do
        begin
          aStream := AutoLoader.OpenFileStream(i);
          Result := FlashStream(aStream, ModelID, True);
          if Result <> 0 then Break;
          // Перериваємо процес у разі помилки
        end;
      finally
        AutoLoader.Free;
      end;
      Exit;
    end
    else if isMFCQ then
    begin
      aStream := FileStream;
    end
    else
    begin
      TConsole.WriteLn('Making QCFM stream');
      ext := ExtractFileExt(fName);
      if (ext <> '') and (ext[1] = '.') then
        Delete(ext, 1, 1);

      iFiles := TStringList.Create;
      try
        iFiles.Add(fName);
        // Запаковуємо звичайний файл у TMFCQPackStream
        aStream := TMFCQPackStream.Create(iFiles, nil, ver, ver = 2, True);
      finally
        iFiles.Free;
        // Звільняємо список після передачі у конструктор
      end;
      // Якщо це вже MFCQ, використовуємо оригінальний FileStream
    end;

    Result := FlashStream(aStream, ModelID, aStream <> FileStream);
  finally
    FileStream.Free;
  end;
end;

function TBBFlasher.FlashStream(aStream: TStream; ModelID: cardinal;
  AutoFreeStream: boolean): integer;
const
  HEADER_SIZE = 8;
var
  Buff: TBytes;
  s, sigSize: int64;
  cb, bs, TotalBlocks: longword;
  progress: IProgressIndicator;
  Success: boolean;
  EffectiveBlockSize: longword;
  StartPos: int64;
  SendSize: integer;
begin
  if not Assigned(fLoader) then
  begin
    TConsole.WriteLn('Loader interface not initialized', ccRed);
    if AutoFreeStream then FreeAndNil(aStream);
    Exit(-2);
  end;

  if not Assigned(aStream) then
  begin
    TConsole.WriteLn('Input stream is nil', ccRed);
    Exit(-1);
  end;

  sigSize := SizeOf(fDummySignature);

  try
    StartPos := aStream.Position;

    if aStream is TMFCQPackStream then
      s := TMFCQPackStream(aStream).PayloadSize
    else
      s := aStream.Size - StartPos;

    if s > SizeOf(fDummySignature) then
    begin
      aStream.Position := StartPos;
      sigSize := GetSignatureBlockSize(aStream);
      if (sigSize <= 0) or (sigSize >= SizeOf(fDummySignature)) then
        sigSize := SizeOf(fDummySignature);
      s := s - sigSize;
    end;

    aStream.Position := StartPos;

    if (ModelID and $FFFF) = $2C0A then
      fLoader.PreFlash($40)
    else
      fLoader.PreFlash($15);

    EffectiveBlockSize := MAX_FLASH_BLOCK - HEADER_SIZE;
    TotalBlocks := (s + EffectiveBlockSize - 1) div EffectiveBlockSize;
    cb := 0;

    // Виділяємо буфер буфера один раз під максимальний розмір
    SetLength(Buff, MAX_FLASH_BLOCK);

    progress := CreateProgressBar(TotalBlocks, 40);
    if Assigned(progress) then progress.Start;

    Success := True;
    try
      while (aStream.Position - StartPos) < s do
      begin
        bs := Min(s - (aStream.Position - StartPos), EffectiveBlockSize);

        PDWord(@Buff[0])^ := cb;
        PDWord(@Buff[4])^ := bs;

        if aStream.Read(Buff[HEADER_SIZE], bs) <> integer(bs) then
        begin
          TConsole.WriteLn('Error reading payload stream', ccRed);
          Success := False;
          Break;
        end;

        SendSize := bs + HEADER_SIZE;
        if SendSize <> MAX_FLASH_BLOCK then
          SetLength(Buff, SendSize);
        // Скорочуємо буфер тільки для останнього блоку

        if not fLoader.SendBlock(Buff) then
        begin
          TConsole.WriteLn('Flash error', ccRed);
          Success := False;
          Break;
        end;

        Inc(cb);
        if Assigned(progress) then progress.Update(cb);
      end;
    finally
      if Assigned(progress) then progress.Stop;
    end;

    if not Success then
      Exit(-3);

    TConsole.WriteLn('Send signature');
    SetLength(Buff, sigSize + 2);
    PWord(@Buff[0])^ := word(sigSize);

    if (aStream is TMFCQPackStream) and TMFCQPackStream(aStream).IsSigned then
      TMFCQPackStream(aStream).Read(Buff[2], sigSize)
    else
      aStream.Read(Buff[2], sigSize);

    if not fLoader.SendSignature(Buff) then
      TConsole.WriteLn('Signature send error', ccRed);

    Sleep(1000);
  finally
    if AutoFreeStream then
      FreeAndNil(aStream);
  end;

  fLoader.Complete;
  TConsole.WriteLn('Done');
  Result := 0;
end;

end.
