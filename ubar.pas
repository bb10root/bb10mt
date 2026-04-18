unit uBar;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  CLI.Command,       // Base command implementation
  CLI.Console;       // Optional: Colored console output

type
  TBARCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;


  TBARCommandTemplate = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TBARCommandUpdate = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TBARCommandIds = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

var
  Bar: TBARCommand;
  BarTemplate: TBARCommandTemplate;
  BarUpdate: TBARCommandUpdate;
  BarIds: TBARCommandIds;

implementation

uses uBarUtils;

function TBarCommand.Execute: integer;
begin
  Result := 0;

end;


function TBarCommandTemplate.Execute: integer;
var
  tmps1, tmps2: string;
  t, u, i, n: boolean;
begin
  if GetParameterValue('--path', tmps1) then
  begin

    tmps1 := ExcludeTrailingPathDelimiter(tmps1);
    if GetParameterValue('--name', tmps2) then
    begin
      TConsole.WriteLn('Create bar template');
      CreateBar(tmps1, tmps2);
      Result := 0;
    end
    else
    begin
      TConsole.WriteLn('Error: you need to specify package name', ccRed);
      Result := 10;
    end;

  end;

end;

function TBARCommandUpdate.Execute: integer;
var
  tmps1: string;
begin
  if GetParameterValue('--path', tmps1) then
  begin

    tmps1 := IncludeTrailingPathDelimiter(tmps1);
    TConsole.WriteLn('Update bar hashes');
    UpdateHashes(tmps1);

  end;

end;

function TBarCommandIds.Execute: integer;
var
  tmps1: string;
begin
  if GetParameterValue('--path', tmps1) then
  begin
    tmps1 := IncludeTrailingPathDelimiter(tmps1);
    TConsole.WriteLn('Update bar package ids');
    UpdateIds(tmps1);
  end;
end;


{$IFDEF LINUX}
type
  TBARCommandInstall = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

var

  BarInstall: TBARCommandInstall;


  function TBARCommandInstall.Execute: integer;
  var
    barPath, mountPath: string;

    function RequireParam(const Param, ErrorMsg: string; out Value: string): boolean;
    begin
      Result := GetParameterValue(Param, Value);
      if not Result then
      begin
        TConsole.WriteLn(ErrorMsg);
        Exit(False);
      end;
      Value := IncludeTrailingPathDelimiter(Value);
    end;

    function CheckDirExists(const Dir, ParamName: string): boolean;
    begin
      Result := DirectoryExists(Dir);
      if not Result then
      begin
        TConsole.WriteLn('Error: directory for ' + ParamName + ' "' + Dir + '" does not exist.');
      end;
    end;

  begin
    if not RequireParam('--path', 'Error: --path parameter is required.', barPath) then Exit(1);
    if not RequireParam('--mount', 'Error: --mount parameter is required.', mountPath) then Exit(1);
    if not CheckDirExists(barPath, '--path') then Exit(2);
    if not CheckDirExists(mountPath, '--mount') then Exit(3);

    TConsole.WriteLn('Installing bar package from "' + barPath + '" to "' + mountPath + '"...');
    InstallUnpackedBar(barPath, mountPath);
    Result := 0;
  end;

{$ENDIF}

initialization

  Bar := TBARCommand.Create('bar', 'Unpacked BAR-files manipulations');

  BarTemplate := TBARCommandTemplate.Create('template', 'Create BAR template');
  BarTemplate.AddPathParameter('-p', '--path', 'Path to base dir', True);
  BarTemplate.AddStringParameter('-n', '--name', 'BAR name', True);

  BarUpdate := TBARCommandUpdate.Create('update', 'update hashes in MANIFEST.MF');
  BarUpdate.AddPathParameter('-p', '--path', 'Path to unpacked BAR', True);

  BarIds := TBARCommandIds.Create('ids', 'new ids in MANIFEST.MF');
  BarIds.AddPathParameter('-p', '--path', 'Path to unpacked BAR', True);

  Bar.AddSubCommand(BarTemplate);
  Bar.AddSubCommand(BarUpdate);
  Bar.AddSubCommand(BarIds);
  {$IFDEF LINUX}
  BarInstall := TBARCommandInstall.Create('install', 'install unpacked BAR into ');
  BarInstall.AddPathParameter('-p', '--path', 'Path to unpacked BAR', True);
  BarInstall.AddPathParameter('-m', '--mount', 'Path to mount point', True);
  Bar.AddSubCommand(BarInstall);
  {$ENDIF}

end.
