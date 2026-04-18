unit uScript;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes;

type
  { Р†РЅС‚РµСЂС„РµР№СЃ РґР»СЏ РєРѕРјР°РЅРґРё }
  ICommand = interface
    ['{F9D9BFA1-4F34-4A8E-91DD-2A1B3F5C7E63}']
    function GetName: string;
    function GetDescription: string;
    function GetUsage: string;
    function Execute(const Args: array of string): integer;
  end;

  { РђР±СЃС‚СЂР°РєС‚РЅРёР№ Р±Р°Р·РѕРІРёР№ РєР»Р°СЃ РґР»СЏ РєРѕРјР°РЅРґ }
  TBasicCommand = class(TInterfacedObject, ICommand)
  private
    FName: string;
    FDescription: string;
    FUsage: string;
  public
    constructor Create(const AName, ADescription, AUsage: string);
    function GetName: string;
    function GetDescription: string;
    function GetUsage: string;
    function Execute(const Args: array of string): integer; virtual; abstract;
  end;

  { Р†РЅС‚РµСЂС„РµР№СЃ РґР»СЏ СЃРїРёСЃРєСѓ РєРѕРјР°РЅРґ }
  ICommandList = interface
    ['{2D5E3B9F-ABC0-4F31-A1A5-ED18B5E8F3C1}']
    procedure RegisterCommand(Cmd: ICommand);
    function FindCommand(const Name: string): ICommand;
    procedure ShowGlobalHelp;
    procedure ExecuteCommand(const Line: string);
  end;

  { ====== РљРѕРјР°РЅРґР° Help ====== }
type
  THelpCommand = class(TBasicCommand)
  private
    FCommandList: ICommandList;
  public
    constructor Create(ACommandList: ICommandList);
    function Execute(const Args: array of string): integer; override;
  end;

  { ====== Р РµР°Р»С–Р·Р°С†С–СЏ ICommandList ====== }

type
  TCommandList = class(TInterfacedObject, ICommandList)
  private
    FCommands: array of ICommand;
  public
    procedure RegisterCommand(Cmd: ICommand);
    function FindCommand(const Name: string): ICommand;
    procedure ShowGlobalHelp;
    procedure ExecuteCommand(const Line: string);
  end;

implementation

{ ====== РџР°СЂСЃРµСЂ Р°СЂРіСѓРјРµРЅС‚С–РІ ====== }

function ParseArgs(const S: string): TStringArray;
var
  i: integer;
  inQuote: boolean;
  arg: string;
  args: TStringList;
  trimmedLine: string;
  hashPos: integer;
begin
  // Р†РіРЅРѕСЂСѓС”РјРѕ РІСЃРµ РїС–СЃР»СЏ #
  hashPos := Pos('#', S);
  if hashPos > 0 then
    trimmedLine := Copy(S, 1, hashPos - 1)
  else
    trimmedLine := S;

  args := TStringList.Create;
  try
    inQuote := False;
    arg := '';
    for i := 1 to Length(trimmedLine) do
    begin
      case trimmedLine[i] of
        '"': inQuote := not inQuote;
        ' ':
          if inQuote then
            arg := arg + trimmedLine[i]
          else if arg <> '' then
          begin
            args.Add(arg);
            arg := '';
          end;
        else
          arg := arg + trimmedLine[i];
      end;
    end;
    if arg <> '' then
      args.Add(arg);
    SetLength(Result, args.Count);
    for i := 0 to args.Count - 1 do
      Result[i] := args[i];
  finally
    args.Free;
  end;
end;

constructor TBasicCommand.Create(const AName, ADescription, AUsage: string);
begin
  FName := AName;
  FDescription := ADescription;
  FUsage := AUsage;
end;

function TBasicCommand.GetName: string;
begin
  Result := FName;
end;

function TBasicCommand.GetDescription: string;
begin
  Result := FDescription;
end;

function TBasicCommand.GetUsage: string;
begin
  Result := FUsage;
end;


procedure TCommandList.RegisterCommand(Cmd: ICommand);
var
  idx: integer;
begin
  idx := Length(FCommands);
  SetLength(FCommands, idx + 1);
  FCommands[idx] := Cmd;
end;

function TCommandList.FindCommand(const Name: string): ICommand;
var
  i: integer;
begin
  for i := 0 to High(FCommands) do
    if SameText(FCommands[i].GetName, Name) then
      Exit(FCommands[i]);
  Result := nil;
end;

procedure TCommandList.ShowGlobalHelp;
var
  i: integer;
begin
  Writeln('Available commands:');
  for i := 0 to High(FCommands) do
    Writeln(Format('  %-15s - %s', [FCommands[i].GetName, FCommands[i].GetDescription]));
  Writeln('Use "<command> --help" for details.');
end;

procedure TCommandList.ExecuteCommand(const Line: string);
var
  Args: TStringArray;
  Cmd: ICommand;
begin
  Args := ParseArgs(Line);
  if Length(Args) = 0 then Exit;

  Cmd := FindCommand(Args[0]);
  if Cmd = nil then
  begin
    Writeln('Unknown command: ', Args[0]);
    Exit;
  end;

  if (Length(Args) = 2) and SameText(Args[1], '--help') then
  begin
    Writeln('Usage: ', Cmd.GetUsage);
    Exit;
  end;

  Cmd.Execute(Copy(Args, 1, Length(Args) - 1));
end;

constructor THelpCommand.Create(ACommandList: ICommandList);
begin
  inherited Create('help', 'Show help for commands', 'help [command]');
  FCommandList := ACommandList;
end;

function THelpCommand.Execute(const Args: array of string): integer;
var
  Cmd: ICommand;
begin
  Result := 0;
  if Length(Args) = 0 then
    FCommandList.ShowGlobalHelp
  else
  begin
    Cmd := FCommandList.FindCommand(Args[0]);
    if Cmd = nil then
      Writeln('Unknown command: ', Args[0])
    else
    begin
      Writeln('Command: ', Cmd.GetName);
      Writeln('Description: ', Cmd.GetDescription);
      Writeln('Usage: ', Cmd.GetUsage);
    end;
  end;
end;

end.
