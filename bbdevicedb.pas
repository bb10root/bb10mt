unit bbdevicedb;

{$mode ObjFPC}{$H+}

interface

uses
  SysUtils;

type
  TFullDeviceInfo = record
    ID: longword;
    ModelCode: string;
    ModelName: string;
    FullName: string;
    Category: string;
  end;

  TModelInfo = record
    ModelName: string;
    FullName: string;
    Category: string;
  end;

  TDeviceInfo = record
    ID: longword;
    ModelCode: string;
    ModelIndex: byte;
  end;

function TryGetDeviceInfoByID(const aID: longword; out aFullInfo: TFullDeviceInfo): boolean;
function IDtoADDR(const ID: cardinal): cardinal;

implementation

const
  DeviceModels: array[0..14] of TModelInfo = (
    (ModelName: 'Classic'; FullName: 'BlackBerry Classic'; Category: 'Bold'),
    (ModelName: 'P''9983'; FullName: 'PORSCHE DESIGN P''9983 BlackBerry'; Category: 'Bold'),
    (ModelName: 'Q10'; FullName: 'BlackBerry Q10'; Category: 'Bold'),
    (ModelName: 'Q5'; FullName: 'BlackBerry Q5'; Category: 'Curve'),
    (ModelName: 'Passport'; FullName: 'BlackBerry Passport'; Category: 'Passport'),
    (ModelName: 'Z30'; FullName: 'BlackBerry Z30'; Category: 'Touch'),
    (ModelName: 'Z3'; FullName: 'BlackBerry Z3'; Category: 'Touch'),
    (ModelName: 'P''9982'; FullName: 'PORSCHE DESIGN P''9982 BlackBerry'; Category: 'Touch'),
    (ModelName: 'Z10'; FullName: 'BlackBerry Z10'; Category: 'Touch'),
    (ModelName: 'Unknown'; FullName: 'Unknown'; Category: 'Unknown'),
    (ModelName: 'Leap'; FullName: 'BlackBerry Leap'; Category: 'Touch'),
    (ModelName: 'Unknown'; FullName: 'BlackBerry Unknown'; Category: 'Unknown'),
    (ModelName: 'Playbook'; FullName: 'BlackBerry Playbook'; Category: 'Playbook'),
    (ModelName: 'Anonymous'; FullName: 'BlackBerry Unknown'; Category: 'Unknown'),
    (ModelName: 'BlackBerry 10 Dev Alpha'; FullName: 'BlackBerry 10 Dev Alpha'; Category: 'Unknown')
  );

  BB10Devices: array[0..52] of TDeviceInfo = (
    (ID: $9600270a; ModelCode: 'SQC100-1'; ModelIndex: 0),
    (ID: $9400270a; ModelCode: 'SQC100-2'; ModelIndex: 0),
    (ID: $9500270a; ModelCode: 'SQC100-3'; ModelIndex: 0),
    (ID: $9700270a; ModelCode: 'SQC100-4'; ModelIndex: 0),
    (ID: $9c00270a; ModelCode: 'SQC100-5'; ModelIndex: 0),
    (ID: $8f00270a; ModelCode: 'SQK100-1'; ModelIndex: 1),
    (ID: $8e00270a; ModelCode: 'SQK100-2'; ModelIndex: 1),
    (ID: $8400270a; ModelCode: 'SQN100-1'; ModelIndex: 2),
    (ID: $8500270a; ModelCode: 'SQN100-2'; ModelIndex: 2),
    (ID: $8600270a; ModelCode: 'SQN100-3'; ModelIndex: 2),
    (ID: $8c00270a; ModelCode: 'SQN100-4'; ModelIndex: 2),
    (ID: $8700270a; ModelCode: 'SQN100-5'; ModelIndex: 2),
    (ID: $84002a0a; ModelCode: 'SQR100-1'; ModelIndex: 3),
    (ID: $85002a0a; ModelCode: 'SQR100-2'; ModelIndex: 3),
    (ID: $86002a0a; ModelCode: 'SQR100-3'; ModelIndex: 3),
    (ID: $87002c0a; ModelCode: 'SQW100-1'; ModelIndex: 4),
    (ID: $85002c0a; ModelCode: 'SQW100-2'; ModelIndex: 4),
    (ID: $84002c0a; ModelCode: 'SQW100-3'; ModelIndex: 4),
    (ID: $8f002c0a; ModelCode: 'SQW100-4'; ModelIndex: 4),
    (ID: $8c00240a; ModelCode: 'STA100-1'; ModelIndex: 5),
    (ID: $8d00240a; ModelCode: 'STA100-2'; ModelIndex: 5),
    (ID: $8e00240a; ModelCode: 'STA100-3'; ModelIndex: 5),
    (ID: $8f00240a; ModelCode: 'STA100-4'; ModelIndex: 5),
    (ID: $9500240a; ModelCode: 'STA100-5'; ModelIndex: 5),
    (ID: $b500240a; ModelCode: 'STA100-6'; ModelIndex: 5),
    (ID: $04002e07; ModelCode: 'STJ100-1'; ModelIndex: 6),
    (ID: $05002e07; ModelCode: 'STJ100-2'; ModelIndex: 6),
    (ID: $a500240a; ModelCode: 'STK100-1'; ModelIndex: 7),
    (ID: $a600240a; ModelCode: 'STK100-2'; ModelIndex: 7),
    (ID: $04002607; ModelCode: 'STL100-1'; ModelIndex: 8),
    (ID: $8700240a; ModelCode: 'STL100-2'; ModelIndex: 8),
    (ID: $8500240a; ModelCode: 'STL100-3'; ModelIndex: 8),
    (ID: $8400240a; ModelCode: 'STL100-4'; ModelIndex: 8),
    (ID: $05002e0a; ModelCode: 'STM100-1'; ModelIndex: 9),
    (ID: $04002e0a; ModelCode: 'STM100-2'; ModelIndex: 9),
    (ID: $07002e0a; ModelCode: 'STR100-1'; ModelIndex: 10),
    (ID: $06002e0a; ModelCode: 'STR100-2'; ModelIndex: 10),
    (ID: $86002c0a; ModelCode: 'Unknown'; ModelIndex: 4),
    (ID: $8c002c0a; ModelCode: 'Unknown'; ModelIndex: 9),
    (ID: $8d002c0a; ModelCode: 'Unknown'; ModelIndex: 4),
    (ID: $8e002c0a; ModelCode: 'Unknown'; ModelIndex: 4),
    (ID: $a400080a; ModelCode: 'Unknown'; ModelIndex: 11),
    (ID: $ae00240a; ModelCode: 'Unknown'; ModelIndex: 11),
    (ID: $af00240a; ModelCode: 'Unknown'; ModelIndex: 11),
    (ID: $b400240a; ModelCode: 'Unknown'; ModelIndex: 11),
    (ID: $b600240a; ModelCode: 'Unknown'; ModelIndex: 11),
    (ID: $bc00240a; ModelCode: 'Unknown'; ModelIndex: 11),
    (ID: $06001a06; ModelCode: 'P100-16WF'; ModelIndex: 12),
    (ID: $0c001a06; ModelCode: 'P150-32LT1'; ModelIndex: 12),
    (ID: $0d001a06; ModelCode: 'P150-32LT2'; ModelIndex: 12),
    (ID: $0e001a06; ModelCode: 'P150-32HS'; ModelIndex: 12),
    (ID: $8500080a; ModelCode: 'PRO100-1'; ModelIndex: 13),
    (ID: $04002307; ModelCode: 'PRO100-2'; ModelIndex: 14)
  );

function TryGetDeviceInfoByID(const aID: longword; out aFullInfo: TFullDeviceInfo): boolean;
var
  Device: TDeviceInfo;
  Model: TModelInfo;
begin
  Result := False;
  aFullInfo := Default(TFullDeviceInfo);

  for Device in BB10Devices do
  begin
    if Device.ID = aID then
    begin
      Model := DeviceModels[Device.ModelIndex];
      aFullInfo.ID := Device.ID;
      aFullInfo.ModelCode := Device.ModelCode;
      aFullInfo.ModelName := Model.ModelName;
      aFullInfo.FullName := Model.FullName;
      aFullInfo.Category := Model.Category;
      Result := True;
      Exit;
    end;
  end;
end;

function IDtoADDR(const ID: cardinal): cardinal;
var
  xID: cardinal;
begin
  xID := ID and $FFFF;
  if ID = $B600240A then Exit($0DD00000);

  case xID of
    $080a, $240a, $270a, $2a0a, $2e0a, $2e07: Result := $80200000;
    $1a06, $2307, $2607, $260a: Result := $80100000;
    $2c0a: Result := $0DD00000;
    else
      Result := $FFFFFFFF;
  end;
end;

end.
