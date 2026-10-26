unit bbtransport;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, LibUsb, LibUsbOop, bbconst, crc, Math;

type
  EUSBError = class(Exception);

  TEndpointPair = record
    InAddr: byte;
    OutAddr: byte;
  end;

  TBBTransport = class
  private
    fUSBContext: TLibUsbContext;
    fDevice: TLibUsbDevice;
    fID: cardinal;

    fClaimedInterface: integer;
    fPacketNum: array[0..2] of word;
    fMode: byte;

    fEndpoints: array[0..3] of TEndpointPair;
    fEPCount: integer;

    function GetEndpoint(Channel: word; IsIn: boolean): byte;
  public
    constructor Create;
    destructor Destroy; override;

    procedure Open(const ProductIDs: array of word; TimeoutMS: integer = 5000);
    function TryOpen(const ProductIDs: array of word; TimeoutMS: integer = 5000): boolean;
    procedure Close;

    function ReadData(var Channel: word; var Data: TBytes): integer;
    function SendData(Channel: word; Data: TBytes): integer;

    function Channel0(var cmd: byte; Data: TBytes): TBytes;
    function Channel1(Data: TBytes): TBytes;
    function Channel2(Cmd: word; var Resp: word; Data: TBytes): TBytes;

    function GetProductIDs(vendorID: word): specialize TArray<word>;

    property ID: cardinal read fID;
    property Mode: byte read fMode write fMode;
  end;

function WaitForDeviceWithID(VendorID, ProductID, timeoutMS: integer): boolean;

implementation

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
  try
    while GetTickCount64 - t0 < QWord(timeoutMS) do
    begin
      cnt := ctx.GetDeviceList(devs);
      if cnt > 0 then
      begin
        try
          for i := 0 to Pred(cnt) do
          begin
            desc := TLibUsbContext.GetDeviceDescriptor(devs[i]);
            if (desc.idVendor = VendorID) and (desc.idProduct = ProductID) then
              Exit(True);
          end;
        finally
          ctx.FreeDeviceList(devs);
        end;
      end;
      Sleep(100);
    end;
  finally
    ctx.Free;
  end;
end;

{ TBBTransport }

constructor TBBTransport.Create;
begin
  inherited Create;
  fUSBContext := TLibUsbContext.Create;
  fDevice := nil;
  fClaimedInterface := -1;
  fMode := $FF;
  fEPCount := 0;
  FillChar(fEndpoints, SizeOf(fEndpoints), 0);
  FillChar(fPacketNum, SizeOf(fPacketNum), 0);
end;

destructor TBBTransport.Destroy;
begin
  Close;
  FreeAndNil(fUSBContext);
  inherited Destroy;
end;

procedure TBBTransport.Close;
begin
  if Assigned(fDevice) then
  begin
    if (fClaimedInterface >= 0) and (fDevice.Handle <> nil) then
    begin
      libusb_release_interface(fDevice.Handle, fClaimedInterface);
      fClaimedInterface := -1;
    end;
    FreeAndNil(fDevice);
  end;
  fID := 0;
  fEPCount := 0;
  FillChar(fEndpoints, SizeOf(fEndpoints), 0);
end;

function TBBTransport.GetEndpoint(Channel: word; IsIn: boolean): byte;
begin
  // 1. Примусовий хардкод під конкретні Product ID пристрою
  if (fID = 1) or (fID = $8001) then
  begin
    if IsIn then Exit($82)
    else
      Exit($02);
  end
  else if fID = $8017 then
  begin
    if IsIn then Exit($87)
    else
      Exit($07);
  end;

  // 2. Якщо fID інший, беремо першу знайдену пару з масиву fEndpoints
  if fEPCount > 0 then
  begin
    if IsIn then
      Result := fEndpoints[0].InAddr
    else
      Result := fEndpoints[0].OutAddr;

    if Result <> 0 then Exit;
  end;

  // 3. Загальний фоллбек
  if IsIn then Result := $81
  else
    Result := $01;
end;

function TBBTransport.TryOpen(const ProductIDs: array of word; TimeoutMS: integer = 5000): boolean;
var
  cfg, i, cnt, t, j, k, epIdx: integer;
  DevList: PPlibusb_device;
  DevDesc: libusb_device_descriptor;
  config: Plibusb_config_descriptor;
  iface: libusb_interface;
  alt: libusb_interface_descriptor;
  ep: libusb_endpoint_descriptor;
  epAddr, epNum: byte;
  isIn: boolean;

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
  Close;

  t := 0;
  repeat
    cnt := fUSBContext.GetDeviceList(DevList);
    if cnt > 0 then
    begin
      try
        for i := 0 to Pred(cnt) do
        begin
          DevDesc := TLibUsbContext.GetDeviceDescriptor(DevList[i]);

          if (DevDesc.idVendor = $0FCA) and IsProductIDMatch(DevDesc.idProduct) then
          begin
            fID := DevDesc.idProduct;
            fDevice := TLibUsbDevice.Create(fUSBContext, DevList[i]);

            if fDevice.Handle = nil then
            begin
              FreeAndNil(fDevice);
              Continue;
            end;

            cfg := fDevice.GetConfiguration;
            if (cfg <> 1) and (libusb_set_configuration(fDevice.Handle, 1) < 0) then
            begin
              FreeAndNil(fDevice);
              Continue;
            end;

            if libusb_get_active_config_descriptor(libusb_get_device(fDevice.Handle), config) <> 0 then
            begin
              FreeAndNil(fDevice);
              Continue;
            end;

            try
              for j := 0 to config^.bNumInterfaces - 1 do
              begin
                {$PUSH}
                {$R-}
                {$Q-}
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
                      fClaimedInterface := alt.bInterfaceNumber;
                      fEPCount := 0;
                      FillChar(fEndpoints, SizeOf(fEndpoints), 0);

                      for k := 0 to alt.bNumEndpoints - 1 do
                      begin
                        {$PUSH}
                        {$R-}
                        {$Q-}
                        ep := alt.endpoint^[k];
                        {$POP}

                        if (ep.bmAttributes and $03) = LIBUSB_TRANSFER_TYPE_BULK then
                        begin
                          epAddr := ep.bEndpointAddress;
                          epNum := epAddr and $0F;
                          isIn := (epAddr and $80) <> 0;

                          epIdx := -1;
                          for epIdx := 0 to fEPCount - 1 do
                          begin
                            if ((fEndpoints[epIdx].InAddr and $0F) = epNum) or
                              ((fEndpoints[epIdx].OutAddr and $0F) = epNum) then
                              Break;
                          end;

                          if (epIdx = -1) or (epIdx >= fEPCount) then
                          begin
                            if fEPCount < Length(fEndpoints) then
                            begin
                              epIdx := fEPCount;
                              Inc(fEPCount);
                            end
                            else
                              Continue;
                          end;

                          if isIn then
                            fEndpoints[epIdx].InAddr := epAddr
                          else
                            fEndpoints[epIdx].OutAddr := epAddr;
                        end;
                      end;

                      FillChar(fPacketNum, SizeOf(fPacketNum), 0);
                      fMode := $FF;
                      Result := True;
                      Break;
                    end;
                  end;
                end;
              end;
            finally
              libusb_free_config_descriptor(config);
            end;

            if Result then
              Break
            else
              FreeAndNil(fDevice);
          end;
        end;
      finally
        fUSBContext.FreeDeviceList(DevList);
      end;

      if Result then Exit(True);
    end;

    Sleep(100);
    Inc(t, 100);
  until t >= TimeoutMS;
end;

procedure TBBTransport.Open(const ProductIDs: array of word; TimeoutMS: integer = 5000);
begin
  if not TryOpen(ProductIDs, TimeoutMS) then
    raise EUSBError.Create('Device with required ProductID(s) not found or could not be opened');
end;

function TBBTransport.ReadData(var Channel: word; var Data: TBytes): integer;
var
  pkt: TBytes;
  err, transferred, dataSize: integer;
  endpoint: byte;
begin
  Result := 0;

  if (fDevice = nil) or (fDevice.Handle = nil) then
    raise EUSBError.Create('Device not initialized');

  endpoint := GetEndpoint(Channel, True);
  SetLength(pkt, MAX_PACKET);

  err := libusb_bulk_transfer(fDevice.Handle, endpoint, @pkt[0], MAX_PACKET, transferred, 1000);

  if err = LIBUSB_ERROR_TIMEOUT then
    raise EUSBError.Create('Timeout while reading from device')
  else if err <> 0 then
    raise EUSBError.CreateFmt('USB read error (%d)', [err]);

  if transferred < 4 then
  begin
    SetLength(Data, 0);
    Exit(0);
  end;

  Channel := PWord(@pkt[0])^;
  dataSize := transferred - 4;
  SetLength(Data, dataSize);
  if dataSize > 0 then
    Move(pkt[4], Data[0], dataSize);

  Result := dataSize;
end;

function TBBTransport.SendData(Channel: word; Data: TBytes): integer;
var
  pkt: TBytes;
  err, transferred: integer;
  size, dataSize: integer;
  endpoint: byte;
begin
  if (fDevice = nil) or (fDevice.Handle = nil) then
    raise EUSBError.Create('Device not opened');

  dataSize := Length(Data);
  size := dataSize + 4;

  SetLength(pkt, size);
  PWord(@pkt[0])^ := Channel;
  PWord(@pkt[2])^ := size;
  if dataSize > 0 then
    Move(Data[0], pkt[4], dataSize);

  endpoint := GetEndpoint(Channel, False);

  err := libusb_bulk_transfer(fDevice.Handle, endpoint, @pkt[0], size, transferred, 1000);

  if err <> 0 then
    raise EUSBError.CreateFmt('USB write error (%d)', [err]);

  Result := transferred;
end;

function TBBTransport.Channel0(var cmd: byte; Data: TBytes): TBytes;
var
  pkt: TBytes;
  Channel, size: word;
begin
  SetLength(Result, 0);
  size := Length(Data);
  SetLength(pkt, size + 4);
  pkt[0] := cmd;
  pkt[1] := fMode;
  PWord(@pkt[2])^ := NtoBE(fPacketNum[0]);
  if size > 0 then
    Move(Data[0], pkt[4], size);

  SendData(0, pkt);
  size := ReadData(Channel, pkt);

  if size >= 2 then
  begin
    cmd := pkt[0];
    fMode := pkt[1];
    if size > 4 then
    begin
      SetLength(Result, size - 4);
      Move(pkt[4], Result[0], size - 4);
    end;
  end;
  Inc(fPacketNum[0]);
end;

function TBBTransport.Channel1(Data: TBytes): TBytes;
var
  pkt: TBytes;
  Channel, dataSize, size: word;
begin
  SetLength(Result, 0);
  dataSize := Length(Data);
  size := dataSize + 10;
  SetLength(pkt, size);
  if dataSize > 0 then
    Move(Data[0], pkt[10], dataSize);
  PDword(@pkt[4])^ := size;
  PWord(@pkt[8])^ := fPacketNum[1];
  Inc(fPacketNum[1]);
  PDword(@pkt[0])^ := crc32(0, @pkt[4], size - 4);

  SendData(1, pkt);
  ReadData(Channel, pkt);

  if Length(pkt) >= 10 then
  begin
    size := Length(pkt) - 10;
    SetLength(Result, size);
    if size > 0 then
      Move(pkt[10], Result[0], size);
  end;

  try
    ReadData(Channel, pkt);
  except
  end;
end;

function TBBTransport.Channel2(Cmd: word; var Resp: word; Data: TBytes): TBytes;
var
  pkt: TBytes;
  Channel, dataSize, size: word;
  crc1, crc2: cardinal;
begin
  SetLength(Result, 0);
  dataSize := Length(Data);
  size := dataSize + 8;
  SetLength(pkt, size);
  PWord(@pkt[2])^ := Cmd;
  if dataSize > 0 then
    Move(Data[0], pkt[4], dataSize);
  PWord(@pkt[0])^ := size;
  PDword(@pkt[dataSize + 4])^ := crc32(0, @pkt[0], dataSize + 4);

  SendData(2, pkt);
  ReadData(Channel, pkt);

  if Channel = 2 then
  begin
    if Length(pkt) >= 8 then
    begin
      size := Length(pkt) - 8;
      Resp := PWord(@pkt[2])^;
      crc1 := crc32(0, @pkt[0], Length(pkt) - 4);
      crc2 := PDword(@pkt[Length(pkt) - 4])^;

      if crc1 <> crc2 then
        Resp := $FFFF;

      if (size > 0) and (Resp <> $15) then
      begin
        SetLength(Result, size);
        Move(pkt[4], Result[0], size);
      end;
    end;

    try
      ReadData(Channel, pkt);
    except
    end;
  end;
end;

function TBBTransport.GetProductIDs(vendorID: word): specialize TArray<word>;
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

  SetLength(Result, cnt);
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
        begin
          if Result[j] = pid then
          begin
            found := True;
            Break;
          end;
        end;

        if not found then
        begin
          Result[uniqueCount] := pid;
          Inc(uniqueCount);
        end;
      end;
    end;

    SetLength(Result, uniqueCount);
  finally
    fUSBContext.FreeDeviceList(DevList);
  end;
end;

end.
