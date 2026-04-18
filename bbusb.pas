
unit bbusb;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, LibUsb, LibUsbOop;

type
  TLoadCallback = procedure(i, s: integer);

  TBBUSB = class

  private
    fUSBContext: TLibUsbContext;
    fDevice: TLibUsbDevice;
    fID: cardinal;

    fClaimedInterface: integer;
    fPacketNum: array[0..2] of word;
    fMode: byte;

  public
    constructor Create;
    destructor Destroy; override;
    procedure Open(const ProductIDs: array of word; TimeoutMS: integer = 5000);
    function TryOpen(const ProductIDs: array of word; TimeoutMS: integer = 5000): boolean;
    procedure Close;

    function GetProductIDs(vendorID: word): specialize TArray<word>;

    procedure Ping0;
    procedure Nuke;
    function GetVar(id, bufSize: word): TBytes;

    function SetMode(mode: byte): boolean;
    function PasswordInfo: boolean;

    procedure SwitchChannel;

    procedure Reboot;

    function GetMetrics: TBytes;
    function GetModelID: longword;
    procedure SendLoader(addr: longword; Loader: TBytes; chunkSize: integer = 2044;
      cb: TLoadCallback = nil);
    procedure RunLoader(addr: longword);

    function Channel0(var cmd: byte; Data: TBytes): TBytes;
    function Channel1(Data: TBytes): TBytes;
    function Channel2(Cmd: word; var Resp: word; Data: TBytes): TBytes;

    function ReadData(var Channel: word; var Data: TBytes): integer;
    function SendData(Channel: word; Data: TBytes): integer;

    property id: cardinal read fID;
  end;

function WaitForDeviceWithID(VendorID, ProductID, timeoutMS: integer): boolean;

implementation

uses crc, Math, uCrypto;

function WaitForDeviceWithID(VendorID, ProductID, timeoutMS: integer): boolean;
var
  t0: QWord;
  ctx: TLibUsbContext;
  devs: PPlibusb_device;
  desc: libusb_device_descriptor;
  i, cnt: integer;
begin
  Result := False;
  t0 := GetTickCount64;
  ctx := TLibUsbContext.Create;

  while GetTickCount64 - t0 < QWord(timeoutMS) do
  begin
    cnt := ctx.GetDeviceList(devs);
    for i := 0 to Pred(cnt) do
    begin
      desc := TLibUsbContext.GetDeviceDescriptor(devs[i]);
      if (desc.idVendor = VendorID) and (desc.idProduct = ProductID) then
      begin
        ctx.FreeDeviceList(devs);
        ctx.Free;
        Exit(True);
      end;
    end;
    ctx.FreeDeviceList(devs);
    Sleep(100);
  end;

  ctx.Free;
end;


const
  MAX_PACKET = $10000; //2 * 1024;

var
  fBootMode: array[0..4] of string = ('RIM REINIT', 'RIM-BootLoader', 'RIM-RAMLoader',
    'RIM UPL', 'RIM-BootNUKE');

const
  CMD_PING = $F000;
  CMD_READ_METRICS = $F001;
  CMD_EXIT = $F002;
  CMD_FRESHNESS_SEAL = $F003;
  CMD_WRITE_RAM = $F004;
  CMD_EXECUTE_RAM = $F005;
  CMD_PASSWORD = $F006;
  CMD_CHANGE_BPS = $F007;
  CMD_DEVICE_NUKE = $F008;
  CMD_WRITE_RAM_SETUP = $F009;
  CMD_WRITE_RAM_VERIFY = $F00A;
  CMD_READ_MODEL_CODE = $F00B;
  CMD_X1 = $F00C;
  CMD_X2 = $F00D;

procedure TBBUSB.Nuke();
var
  Data: TBytes;
  Channel: word;
begin
  SetLength(Data, 2);
  PWord(@Data[0])^ := CMD_DEVICE_NUKE;
//  PDWord(@Data[2])^ := addr;
  Data := Channel1(Data);
  ReadData(Channel, Data);
end;

procedure TBBUSB.RunLoader(addr: longword);
var
  Data: TBytes;
  Channel: word;
begin
  SetLength(Data, 6);
  PWord(@Data[0])^ := CMD_EXECUTE_RAM;
  PDWord(@Data[2])^ := addr;
  Data := Channel1(Data);
  ReadData(Channel, Data);
end;

procedure TBBUSB.SendLoader(addr: longword; Loader: TBytes; chunkSize: integer = 2044;
  cb: TLoadCallback = nil);
//const
//  chunkSize = 2044 - 10 - 10;//256
//  chunkSize = 280 - 10 - 10;//256
var
  pkt, Data: TBytes;
  p, i, s, size: integer;
begin
  SetLength(Data, 10);
  size := Length(Loader);
  PWord(@Data[0])^ := CMD_WRITE_RAM_SETUP;
  PDWord(@Data[2])^ := addr;
  PDWord(@Data[6])^ := size;
  Data := Channel1(Data);
  p := size;
  SetLength(pkt, chunkSize + 10);

  i := 0;
  while p > 0 do
  begin
    s := Min(chunkSize, p);
    if s < chunkSize then
      setLength(pkt, s + 10);
    PWord(@pkt[0])^ := CMD_WRITE_RAM;
    PDWord(@pkt[2])^ := addr + i;
    PDWord(@pkt[6])^ := s;
    move(Loader[i], pkt[10], s);
    Data := Channel1(pkt);

    Dec(p, s);
    Inc(i, s);
    if cb <> nil then
      cb(i, size);
  end;
  if cb <> nil then
    cb(size, size);
  SetLength(pkt, 2);
  PWord(@pkt[0])^ := CMD_WRITE_RAM_VERIFY;
  Data := Channel1(pkt);
end;

function TBBUSB.GetMetrics: TBytes;
var
  Data: TBytes;
begin
  SetLength(Data, 2);
  PWord(@Data[0])^ := CMD_READ_METRICS;
  Result := Channel1(Data);
end;

function TBBUSB.GetModelID: longword;
var
  Data: TBytes;
begin
  SetLength(Data, 2);
  PWord(@Data[0])^ := CMD_READ_MODEL_CODE;
  Data := Channel1(Data);
  if Length(Data) < 14 then
    raise Exception.CreateFmt('Unexpected response size: %d bytes', [Length(Data)]);

  Move(Data[10], Result, 4);
end;


procedure TBBUSB.Ping0;
var
  cmd: byte = 1;
begin
  Channel0(cmd, [$14, $05, $83, $19, $00, $00, $00, $00]);
end;

function TBBUSB.GetVar(id, bufSize: word): TBytes;
var
  cmd: byte = 5;
  Data: TBytes;
begin
  SetLength(Data, 4);
  PWord(@Data[0])^ := bufSize;
  PWord(@Data[2])^ := id;
  Result := Channel0(cmd, Data);
  if cmd <> 6 then Result := [];
end;


procedure TBBUSB.SwitchChannel;
var
  Data: TBytes;
  Channel: word;
begin
  SendData(1, [6, 6]);
  ReadData(Channel, Data);
  ReadData(Channel, Data);
  fPacketNum[1] := 0;
end;

procedure TBBUSB.Reboot;
var
  cmd: byte = 3;
begin
  Channel0(cmd, []);
  fPacketNum[0] := 0;
end;

// 5
// 11
// 15
// 18

function TBBUSB.Channel0(var cmd: byte; Data: TBytes): TBytes;
var
  pkt: TBytes;
  Channel, size: word;
begin
  size := Length(Data);
  SetLength(pkt, size + 4);
  pkt[0] := cmd;
  pkt[1] := fMode;
  PWord(@pkt[2])^ := NtoBE(fPacketNum[0]);
  if size > 0 then
    move(Data[0], pkt[4], size);
  SendData(0, pkt);
  size := ReadData(Channel, pkt);

  cmd := pkt[0];
  fMode := pkt[1];
  if size > 4 then
  begin
    SetLength(Result, size - 4);
    Move(pkt[4], Result[0], size - 4);
  end;
  Inc(fPacketNum[0]);
end;

function TBBUSB.Channel1(Data: TBytes): TBytes;
var
  pkt: TBytes;
  Channel, dataSize, size: word;
begin
  dataSize := length(Data);
  size := dataSize + 10;
  setLength(pkt, size);
  move(Data[0], pkt[10], dataSize);
  PDword(@pkt[4])^ := size;
  PWord(@pkt[8])^ := fPacketNum[1];
  Inc(fPacketNum[1]);
  PDword(@pkt[0])^ := crc32(0, @pkt[4], size - 4);

  SendData(1, pkt);
  ReadData(Channel, pkt);
  size := max(0, Length(pkt) - 10);
  SetLength(Result, size);
  if size > 0 then
    move(pkt[10], Result[0], size);
  ReadData(Channel, pkt);
end;

function TBBUSB.Channel2(Cmd: word; var Resp: word; Data: TBytes): TBytes;
var
  pkt: TBytes;
  Channel, dataSize, size: word;
  crc1, crc2: cardinal;
begin
  dataSize := length(Data);
  size := dataSize + 8;
  setLength(pkt, size);
  PWord(@pkt[2])^ := Cmd;
  if dataSize > 0 then
    move(Data[0], pkt[4], dataSize);
  PWord(@pkt[0])^ := size;
  PDword(@pkt[dataSize + 4])^ := crc32(0, @pkt[0], dataSize + 4);

  SendData(2, pkt);
  ReadData(Channel, pkt);
  if Channel = 2 then
  begin
    size := max(0, Length(pkt) - 8);
    SetLength(Result, size);
    Resp := PWord(@Pkt[2])^;
    crc1 := crc32(0, @pkt[0], size + 4);
    crc2 := PDword(@pkt[size + 4])^;
    if crc1 <> crc2 then Resp := $FFFF;
    if (size > 0) and (Resp <> $15) then
      move(pkt[4], Result[0], size)
    else
      SetLength(Result, 0);

    ReadData(Channel, pkt);
  end;
end;


function TBBUSB.PasswordInfo: boolean;
var
  cmd: byte = $A;
  Channel: word;
  challengeData, challenge, salt, hashedData, buf: TBytes;
  iterations, i: integer;
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
        on E: Exception do
        begin
        end;
      end;
      Exit(True);
    end
    else if cmd = $0E then
    begin
      if aPassword <> '' then WriteLn('Wrong password!');
      if (challengeData[1] - challengeData[0]) = 2 then Exit(False);
      WriteLn(Format('Enter password (%d/%d):', [challengeData[0], challengeData[1]]));
      repeat
        ReadLn(aPassword);
        aPassword := trim(aPassword);
      until aPassword <> '';

      // 3. Виділяємо частини: challenge, salt, iteration count
      SetLength(challenge, 4);
      //Move(challengeData[4], challenge[0], 4);
      PDword(@challenge[0])^ := PDword(@challengeData[4])^;
      SetLength(salt, 8);
      //Move(challengeData[12], salt[0], 8);
      PQword(@salt[0])^ := PQword(@challengeData[12])^;

      //Move(challengeData[20], iterations, 4); // LE
      iterations := PDword(@challengeData[20])^;

      hashedData := HashPassV2(challenge, salt, aPassword, iterations);

      // prepend 0x00004000 (LE dword) = [0x00, 0x40, 0x00, 0x00]
      SetLength(hashedData, Length(hashedData) + 4);
      for i := High(hashedData) downto 4 do
        hashedData[i] := hashedData[i - 4];
      hashedData[0] := $00;
      hashedData[1] := $00;
      hashedData[2] := $40;
      hashedData[3] := $00;
      cmd := $0F;
    end;
  end;
end;

function TBBUSB.SetMode(mode: byte): boolean;
var
  Data: TBytes;
  l: integer;
  cmd: byte = 7;
  Channel: word;
begin
  l := length(fBootMode[mode]);
  SetLength(Data, 17);
  FillChar(Data[0], 16, 0);
  move(fBootMode[mode][1], Data[0], l);
  Data[16] := 1;
  Data := Channel0(cmd, Data);
  Result := cmd = 8;
end;

function TBBUSB.ReadData(var Channel: word; var Data: TBytes): integer;
var
  pkt: TBytes;
  err, transferred, dataSize: integer;
  endpoint: byte;
begin
  Result := 0;

  // Захист від неініціалізованого пристрою
  if (fDevice = nil) or (fDevice.Handle = nil) then
    raise EUSBError.Create('Device not initialized');

  // Визначення endpoint для читання
  if (fID = 1) or (fID = $8001) then
    endpoint := $82
  else if fID = $8017 then
    endpoint := $87
  else
    endpoint := $81;

  SetLength(pkt, MAX_PACKET);

  err := libusb_bulk_transfer(fDevice.Handle, endpoint, @pkt[0], MAX_PACKET, transferred, 1000);

  if err = LIBUSB_ERROR_TIMEOUT then
    raise EUSBError.Create('Timeout while reading from device')
  else if err <> 0 then
    raise EUSBError.CreateFmt('USB read error (%d)', [err]);

  if transferred < 4 then Exit(0);

  Channel := PWord(@pkt[0])^;
  dataSize := transferred - 4;
  SetLength(Data, dataSize);
  if dataSize > 0 then
    Move(pkt[4], Data[0], dataSize);

  Result := dataSize;
end;

function TBBUSB.SendData(Channel: word; Data: TBytes): integer;
var
  pkt: TBytes;
  err, transferred: integer;
  size, dataSize: integer;
  endpoint: byte;
begin
  if (fDevice = nil) or (fDevice.Handle = nil) then
    raise Exception.Create('Device not opened');

  dataSize := Length(Data);
  size := dataSize + 4;

  if size = 0 then
    raise Exception.Create('Zero-length packet');

  SetLength(pkt, size);
  PWord(@pkt[0])^ := Channel;
  PWord(@pkt[2])^ := size;
  if dataSize > 0 then
    Move(Data[0], pkt[4], dataSize);

  // Вибір endpoint для запису
  if (fID = 1) or (fID = $8001) then
    endpoint := $02
  else if fID = $8017 then
    endpoint := $07
  else
    endpoint := $01;

  err := libusb_bulk_transfer(fDevice.Handle, endpoint, @pkt[0], size, transferred, 1000);

  if err <> 0 then
    raise EUSBError.CreateFmt('USB write error (%d)', [err]);

  Result := transferred;
end;

function TBBUSB.TryOpen(const ProductIDs: array of word; TimeoutMS: integer = 5000): boolean;
var
  cfg, i, cnt, t, j: integer;
  DevList: PPlibusb_device;
  DevDesc: libusb_device_descriptor;
  config: Plibusb_config_descriptor;
  iface: libusb_interface;
  alt: libusb_interface_descriptor;
  productMatches: boolean;

  function IsProductIDMatch(pid: word): boolean;
  var
    p: word;
  begin
    if Length(ProductIDs) = 0 then
      Exit(True);
    for p in ProductIDs do
      if p = pid then
        Exit(True);
    Result := False;
  end;

begin
  Result := False;
  fID := 0;
  t := 0;

  if Assigned(fDevice) then
  begin
    fDevice.Free;
    fDevice := nil;
  end;

  repeat
    cnt := fUSBContext.GetDeviceList(DevList);
  try
    for i := 0 to Pred(cnt) do
    begin
      DevDesc := TLibUsbContext.GetDeviceDescriptor(DevList[i]);

      if DevDesc.idVendor = $0FCA then
      begin
        if not IsProductIDMatch(DevDesc.idProduct) then
          Continue;

        try
          fID := DevDesc.idProduct;
          fDevice := TLibUsbDevice.Create(fUSBContext, DevList[i]);

          if fDevice.Handle = nil then
            Exit; // некоректний дескриптор

          cfg := fDevice.GetConfiguration;
          if (cfg <> 1) and (libusb_set_configuration(fDevice.Handle, 1) < 0) then
            Exit;

          if libusb_get_active_config_descriptor(libusb_get_device(fDevice.Handle), config) <> 0 then
            Exit;

          for j := 0 to config^.bNumInterfaces - 1 do
          begin
            {$PUSH}
            {$R-}
            iface := config^._interface^[j];
            {$POP}
            if iface.num_altsetting < 1 then
              Continue;

            alt := iface.altsetting^[0];

            if alt.bInterfaceClass = $FF then
            begin
              if libusb_kernel_driver_active(fDevice.Handle, alt.bInterfaceNumber) = 0 then
              begin
                if libusb_claim_interface(fDevice.Handle, alt.bInterfaceNumber) = 0 then
                begin
                  // Успішне відкриття інтерфейсу
                  fClaimedInterface := alt.bInterfaceNumber;
                  fPacketNum[0] := 0;
                  fPacketNum[1] := 0;
                  fPacketNum[2] := 0;
                  fMode := $FF;

                  libusb_free_config_descriptor(config);
                  Exit(True);
                end;
              end;
            end;
          end;

          libusb_free_config_descriptor(config);

          // Якщо не вдалося жоден інтерфейс — чистимо
          fDevice.Free;
          fDevice := nil;
        except
          if Assigned(fDevice) then
          begin
            fDevice.Free;
            fDevice := nil;
          end;
        end;
      end;
    end;
  finally
    fUSBContext.FreeDeviceList(DevList);
  end;

    Sleep(100);
    Inc(t, 100);
  until t >= TimeoutMS;
end;


procedure TBBUSB.Open(const ProductIDs: array of word; TimeoutMS: integer = 5000);
begin
  if not TryOpen(ProductIDs, TimeoutMS) then
    raise EUSBError.Create('Device with required ProductID(s) not found or could not be opened');
end;


procedure TBBUSB.Close;
begin
  if Assigned(fDevice) then
  begin
    libusb_release_interface(fDevice.Handle, 0);
    libusb_release_interface(fDevice.Handle, 1);
    FreeAndNil(fDevice);
  end;
  fID := 0;
end;


constructor TBBUSB.Create;
begin
  fUSBContext := TLibUsbContext.Create;
  fDevice := nil;
  fMode := $FF;
  fPacketNum[0] := 0;
end;

destructor TBBUSB.Destroy;
begin
  Close;
  fUSBContext.Free;
end;


function TBBUSB.GetProductIDs(vendorID: word): specialize TArray<word>;
var
  DevList: PPlibusb_device;
  cnt, i, j, uniqueCount: integer;
  DevDesc: libusb_device_descriptor;
  pid: word;
  found: boolean;
begin
  SetLength(Result, 0);

  cnt := fUSBContext.GetDeviceList(DevList);
  if cnt <= 0 then Exit;

  SetLength(Result, cnt); // максимально можливий розмір
  uniqueCount := 0;

  try
    for i := 0 to Pred(cnt) do
    begin
      DevDesc := TLibUsbContext.GetDeviceDescriptor(DevList[i]);
      if DevDesc.idVendor = vendorID then
      begin
        pid := DevDesc.idProduct;

        found := False;
        for j := 0 to uniqueCount - 1 do
          if Result[j] = pid then
          begin
            found := True;
            Break;
          end;

        if not found then
        begin
          Result[uniqueCount] := pid;
          Inc(uniqueCount);
        end;
      end;
    end;

    SetLength(Result, uniqueCount); // обрізаємо під реальну кількість
  finally
    fUSBContext.FreeDeviceList(DevList);
  end;
end;

initialization

finalization
end.
