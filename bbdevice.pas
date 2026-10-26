unit bbdevice;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Math, bbconst, bbtransport, uCrypto;

type
  TBBDevice = class(TBBTransport)
  public
    procedure Ping0;
    procedure Nuke;
    function GetVar(fid, bufSize: word): TBytes;

    function SetMode(fmode: byte): boolean;
    function PasswordInfo: boolean;

    procedure SwitchChannel;
    procedure Reboot;

    function GetMetrics: TBytes;
    function GetModelID: longword;
    procedure SendLoader(addr: longword; Loader: TBytes; chunkSize: integer = 2044;
      cb: TLoadCallback = nil);
    procedure RunLoader(addr: longword);
  end;

implementation

{ TBBDevice }

function TBBDevice.SetMode(fmode: byte): boolean;
var
  Data: TBytes;
  l: integer;
  cmd: byte = 7;
begin
  if fmode > High(BOOT_MODES) then
    Exit(False);

  l := Length(BOOT_MODES[fmode]);
  SetLength(Data, 17);
  FillChar(Data[0], 17, 0);
  if l > 0 then
    Move(BOOT_MODES[fmode][1], Data[0], Min(l, 16));
  Data[16] := 1;

  Data := Channel0(cmd, Data);
  Result := (cmd = 8);
end;

function TBBDevice.PasswordInfo: boolean;
var
  cmd: byte = $A;
  Channel: word;
  challengeData, challenge, salt, rawHash, hashedData: TBytes;
  iterations, origLen: integer;
  aPassword: string = '';
begin
  Result := False;
  while True do
  begin
    challengeData := Channel0(cmd, hashedData);
    if cmd = $10 then
    begin
      try
        ReadData(Channel, challengeData);
      except
      end;
      Exit(True);
    end;

    if cmd = $0E then
    begin
      if Length(challengeData) < 24 then
        Exit(False);

      if aPassword <> '' then
        WriteLn('Wrong password!');

      if (challengeData[1] - challengeData[0]) = 2 then
        Exit(False);

      WriteLn(Format('Enter password (%d/%d):', [challengeData[0], challengeData[1]]));
      repeat
        ReadLn(aPassword);
        aPassword := Trim(aPassword);
      until aPassword <> '';

      SetLength(challenge, 4);
      Move(challengeData[4], challenge[0], 4);

      SetLength(salt, 8);
      Move(challengeData[12], salt[0], 8);

      iterations := PDword(@challengeData[20])^;

      rawHash := HashPassV2(challenge, salt, aPassword, iterations);
      origLen := Length(rawHash);

      SetLength(hashedData, origLen + 4);
      hashedData[0] := $00;
      hashedData[1] := $00;
      hashedData[2] := $40;
      hashedData[3] := $00;
      if origLen > 0 then
        Move(rawHash[0], hashedData[4], origLen);

      cmd := $0F;
    end;
  end;
end;

procedure TBBDevice.Nuke;
var
  Data: TBytes;
  Channel: word;
begin
  SetLength(Data, 2);
  PWord(@Data[0])^ := CMD_DEVICE_NUKE;
  Data := Channel1(Data);
  try
    ReadData(Channel, Data);
  except
  end;
end;

procedure TBBDevice.RunLoader(addr: longword);
var
  Data: TBytes;
  Channel: word;
begin
  SetLength(Data, 6);
  PWord(@Data[0])^ := CMD_EXECUTE_RAM;
  PDWord(@Data[2])^ := addr;
  Data := Channel1(Data);
  try
    ReadData(Channel, Data);
  except
  end;
end;

procedure TBBDevice.SendLoader(addr: longword; Loader: TBytes; chunkSize: integer = 2044;
  cb: TLoadCallback = nil);
var
  pkt, Data: TBytes;
  p, i, s, size: integer;
begin
  size := Length(Loader);
  SetLength(Data, 10);
  PWord(@Data[0])^ := CMD_WRITE_RAM_SETUP;
  PDWord(@Data[2])^ := addr;
  PDWord(@Data[6])^ := size;
  Channel1(Data);

  p := size;
  i := 0;

  while p > 0 do
  begin
    s := Min(chunkSize, p);
    SetLength(pkt, s + 10);

    PWord(@pkt[0])^ := CMD_WRITE_RAM;
    PDWord(@pkt[2])^ := addr + i;
    PDWord(@pkt[6])^ := s;
    Move(Loader[i], pkt[10], s);
    Channel1(pkt);

    Dec(p, s);
    Inc(i, s);
    if Assigned(cb) then
      cb(i, size);
  end;

  if Assigned(cb) then
    cb(size, size);

  SetLength(pkt, 2);
  PWord(@pkt[0])^ := CMD_WRITE_RAM_VERIFY;
  Channel1(pkt);
end;

function TBBDevice.GetMetrics: TBytes;
var
  Data: TBytes;
begin
  SetLength(Data, 2);
  PWord(@Data[0])^ := CMD_READ_METRICS;
  Result := Channel1(Data);
end;

function TBBDevice.GetModelID: longword;
var
  Data: TBytes;
begin
  Result := 0;
  SetLength(Data, 2);
  PWord(@Data[0])^ := CMD_READ_MODEL_CODE;
  Data := Channel1(Data);
  if Length(Data) < 14 then
    raise EUSBError.CreateFmt('Unexpected response size: %d bytes', [Length(Data)]);

  Move(Data[10], Result, 4);
end;

procedure TBBDevice.Ping0;
var
  cmd: byte = 1;
  p: TBytes;
begin
  SetLength(p, 8);
  p[0] := $14;
  p[1] := $05;
  p[2] := $83;
  p[3] := $19;
  p[4] := $00;
  p[5] := $00;
  p[6] := $00;
  p[7] := $00;
  Channel0(cmd, p);
end;

function TBBDevice.GetVar(fid, bufSize: word): TBytes;
var
  cmd: byte = 5;
  Data: TBytes;
begin
  SetLength(Data, 4);
  PWord(@Data[0])^ := bufSize;
  PWord(@Data[2])^ := fid;
  Result := Channel0(cmd, Data);
  if cmd <> 6 then
    SetLength(Result, 0);
end;

procedure TBBDevice.SwitchChannel;
var
  Data, pkt: TBytes;
  Channel: word;
begin
  SetLength(pkt, 2);
  pkt[0] := 6;
  pkt[1] := 6;
  SendData(1, pkt);
  try
    ReadData(Channel, Data);
    ReadData(Channel, Data);
  except
  end;
end;

procedure TBBDevice.Reboot;
var
  cmd: byte = 3;
begin
  Channel0(cmd, []);
end;

end.
