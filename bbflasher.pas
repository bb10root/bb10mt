unit bbflasher;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Math, bbconst, bbLoader, qcfm, CLI.Interfaces, CLI.Progress, CLI.Console;

type
  TBBFlasher = class
  private
    fLoader: TBBLoader;
    fDummySignature: array[0..559] of byte;
  public
    constructor Create(aLoader: TBBLoader);
    function FlashFile(const fName: string; ModelID: cardinal; ver: byte = 2): integer;
  end;

implementation

constructor TBBFlasher.Create(aLoader: TBBLoader);
begin
  inherited Create;
  fLoader := aLoader;
  FillChar(fDummySignature[0], SizeOf(fDummySignature), 0);
end;

function TBBFlasher.FlashFile(const fName: string; ModelID: cardinal; ver: byte = 2): integer;
var
  fPayload: TStream;
  Buff: TBytes;
  s: int64;
  cb, bs, TotalBlocks, MagicVal: longword;
  progress: IProgressIndicator;
  iFiles: TStringList;
  isMFCQ: boolean;
begin
  if not Assigned(fLoader) then
  begin
    TConsole.WriteLn('Loader interface not initialized', ccRed);
    Exit(-2);
  end;

  if not FileExists(fName) then
  begin
    TConsole.WriteLn('File not found: ' + fName, ccRed);
    Exit(-1);
  end;

  fPayload := nil;
  try
    fPayload := TFileStream.Create(fName, fmOpenRead or fmShareDenyNone);
    isMFCQ := False;

    if fPayload.Size >= 4 then
    begin
      if fPayload.Read(MagicVal, SizeOf(MagicVal)) = 4 then
        isMFCQ := (MagicVal = $7163666D); // Magic 'mfcq'
    end;

    if not isMFCQ then
    begin
      FreeAndNil(fPayload);
      TConsole.WriteLn('Making QCFM stream');

      iFiles := TStringList.Create;
      try
        iFiles.Add(fName);
        fPayload := TMFCQPackStream.Create(iFiles, nil, ver, ver = 2, True);
      finally
        iFiles.Free;
      end;
    end
    else
      fPayload.Position := 0;

    if fPayload is TMFCQPackStream then
      s := TMFCQPackStream(fPayload).PayloadSize
    else
      s := fPayload.Size;

    if isMFCQ and (s > 560) then
    begin
      fPayload.Position := s - 560;
      if fPayload.Read(MagicVal, SizeOf(MagicVal)) = 4 then
      begin
        if MagicVal = $48584e51 then // Magic 'QNXH'
        begin
          fPayload.Position := s - 560;
          if fPayload.Read(fDummySignature[0], 560) <> 560 then
            TConsole.WriteLn('Warning: Could not read complete signature', ccYellow);
          s := s - 560;
        end;
      end;
    end;

    fPayload.Position := 0;

    if (ModelID and $FFFF) = $2c0a then
      fLoader.PreFlash($40)
    else
      fLoader.PreFlash($15);

    SetLength(Buff, MAX_FLASH_BLOCK);
    TotalBlocks := (s + (MAX_FLASH_BLOCK - 8) - 1) div (MAX_FLASH_BLOCK - 8);
    cb := 0;

    progress := CreateProgressBar(TotalBlocks, 40);
    if Assigned(progress) then progress.Start;

    try
      while fPayload.Position < s do
      begin
        bs := Min(s - fPayload.Position, MAX_FLASH_BLOCK - 8);

        PDWord(@Buff[0])^ := cb;
        PDWord(@Buff[4])^ := bs;

        if fPayload.Read(Buff[8], bs) <> integer(bs) then
        begin
          TConsole.WriteLn('Error reading file data', ccRed);
          Break;
        end;

        if (bs + 8) <> MAX_FLASH_BLOCK then
          SetLength(Buff, bs + 8);

        if not fLoader.SendBlock(Buff) then
        begin
          TConsole.WriteLn('Flash error', ccRed);
          Exit(-3);
        end;

        Inc(cb);
        if Assigned(progress) then progress.Update(cb);
      end;
    finally
      if Assigned(progress) then progress.Stop;
    end;

    TConsole.WriteLn('Send signature');
    SetLength(Buff, 560 + 2);
    PWord(@Buff[0])^ := word(560);
    if (fPayload is TMFCQPackStream) and (TMFCQPackStream(fPayload).IsSigned) then
    begin
      TMFCQPackStream(fPayload).Read(Buff[2], 560);
    end
    else
    begin
      Move(fDummySignature[0], Buff[2], 560);
    end;

    if not fLoader.SendSignature(Buff) then
      TConsole.WriteLn('Signature send error', ccRed);

    Sleep(1000);
  finally
    FreeAndNil(fPayload);
  end;

  fLoader.Complete;
  TConsole.WriteLn('Done');
  Result := 0;
end;

end.