unit bbclient;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, bbconst, bbtransport, bbdevice, bbloader;

type
  TBBClient = class
  private
    fDevice: TBBDevice;
    fLoader: TBBLoader;
    function GetIsConnected: boolean;
  public
    constructor Create;
    destructor Destroy; override;

    function Connect(const ProductIDs: array of word;
      TimeoutMS: integer = 5000): boolean;
    procedure Disconnect;

    // Перезавантаження з очікуванням повторного підключення
    function RebootAndReconnect(const TargetProductIDs: array of word;
      WaitDisconnectMS: integer = 3000; ReconnectTimeoutMS: integer = 10000): boolean;

    function BootstrapLoader(addr: longword; LoaderData: TBytes;
      cb: TLoadCallback = nil): boolean;
    function GetDeviceSummary(out PinHex: string; out ModelID: longword): boolean;

    property Device: TBBDevice read fDevice;
    property Loader: TBBLoader read fLoader;
    property IsConnected: boolean read GetIsConnected;
  end;

implementation

constructor TBBClient.Create;
begin
  inherited Create;
  fDevice := TBBDevice.Create;
  fLoader := TBBLoader.Create(fDevice);
end;

destructor TBBClient.Destroy;
begin
  FreeAndNil(fLoader);
  FreeAndNil(fDevice);
  inherited Destroy;
end;

function TBBClient.GetIsConnected: boolean;
begin
  Result := Assigned(fDevice) and (fDevice.ID <> 0);
end;

function TBBClient.Connect(const ProductIDs: array of word;
  TimeoutMS: integer = 5000): boolean;
begin
  Result := fDevice.TryOpen(ProductIDs, TimeoutMS);
end;

procedure TBBClient.Disconnect;
begin
  fDevice.Close;
end;

function TBBClient.RebootAndReconnect(const TargetProductIDs: array of word;
  WaitDisconnectMS: integer = 3000; ReconnectTimeoutMS: integer = 10000): boolean;
var
  t0: QWord;
  currentID: word;
begin
  Result := False;
  if not IsConnected then Exit;

  currentID := fDevice.ID;

  try
    if (currentID = $8001) then
      fLoader.Reboot;
    fDevice.Reboot;
  except
    // Ігноруємо помилки USB write/read, оскільки пристрій міг відключитися миттєво
  end;

  // 2. Закриваємо поточну сесію USB
  Disconnect;

  // 3. Очікуємо фізичного від'єднання пристрою від шини USB
  t0 := GetTickCount64;
  while (GetTickCount64 - t0 < QWord(WaitDisconnectMS)) do
  begin
    // Перевіряємо, чи зник пристрій із цим Vendor/Product ID з переліку
    if not WaitForDeviceWithID($0FCA, currentID, 100) then
      Break;
    Sleep(100);
  end;

  // 4. Очікуємо підключення нового або перезавантаженого пристрою
  // Якщо TargetProductIDs порожній, шукаємо пристрій за поточним ID
  if Length(TargetProductIDs) = 0 then
    Result := Connect([currentID], ReconnectTimeoutMS)
  else
    Result := Connect(TargetProductIDs, ReconnectTimeoutMS);
end;

function TBBClient.BootstrapLoader(addr: longword; LoaderData: TBytes;
  cb: TLoadCallback = nil): boolean;
begin
  Result := False;
  if not IsConnected then Exit;

  try
    fDevice.SendLoader(addr, LoaderData, 2044, cb);
    fDevice.RunLoader(addr);
    Sleep(500);
    Result := True;
  except
    Result := False;
  end;
end;

function TBBClient.GetDeviceSummary(out PinHex: string; out ModelID: longword): boolean;
var
  rawPin: DWord;
begin
  Result := False;
  PinHex := '';
  ModelID := 0;

  if not IsConnected then Exit;

  try
    ModelID := fDevice.GetModelID;
    rawPin := fLoader.PIN;
    PinHex := Format('0x%.8X', [rawPin]);
    Result := True;
  except
    Result := False;
  end;
end;

end.
