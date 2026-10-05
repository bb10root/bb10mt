unit uNet;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils,
  CLI.Interfaces,    // Core interfaces
  CLI.Command,       // Base command implementation
  CLI.Progress,      // Optional: Progress indicators
  CLI.Console;       // Optional: Colored console output

type
  TNETCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

var
  NETCommand: TNETCommand;

implementation

uses
  {$IFDEF UNIX}
  BaseUnix, UnixType, termio,
  {$ENDIF}
  {$IFDEF MSWINDOWS}
  Windows,
  {$ENDIF}
  bb_usb_detect, MainNet, logger, bbcgi;

var
  Stop: boolean = False;

{$IFDEF UNIX}
procedure HandleSigInt(sig: cint); cdecl;
begin
  Stop := True;
end;

function KeyPressed: Boolean;
var
  IOCtlResult, BytesAvailable: LongInt;
begin
  BytesAvailable := 0;
  IOCtlResult := fpIOCtl(0, FIONREAD, @BytesAvailable);
  Result := (IOCtlResult = 0) and (BytesAvailable > 0);
end;

function ReadKey: Char;
var
  ReadBytes: LongInt;
begin
  Result := #0;
  ReadBytes := fpRead(0, @Result, 1);
  if ReadBytes <= 0 then
    Result := #0;
end;
{$ENDIF}

{$IFDEF MSWINDOWS}
function ConsoleHandler(dwCtrlType: DWORD): BOOL; stdcall;
begin
  if (dwCtrlType = CTRL_C_EVENT) or (dwCtrlType = CTRL_BREAK_EVENT) then
  begin
    Stop := True;
    Result := True;
    Exit;
  end;
  Result := False;
end;

function KeyPressed: boolean;
var
  hIn: THandle;
  NumEvents, ReadEvents: DWORD;
  Buf: TInputRecord;
begin
  Result := False;
  hIn := GetStdHandle(STD_INPUT_HANDLE);
  if GetNumberOfConsoleInputEvents(hIn, NumEvents) and (NumEvents > 0) then
  begin
    // Переглядаємо події, щоб переконатися, що це саме натискання клавіші (KeyDown)
    if PeekConsoleInput(hIn, Buf, 1, ReadEvents) and (ReadEvents > 0) then
    begin
      if (Buf.EventType = KEY_EVENT) and Buf.Event.KeyEvent.bKeyDown then
        Exit(True)
      else
      begin
        // Вилучаємо з буфера непотрібні події (рух миші, KeyUp тощо), щоб уникнути зациклення
        ReadConsoleInput(hIn, Buf, 1, ReadEvents);
      end;
    end;
  end;
end;

function ReadKey: char;
var
  Buf: TInputRecord;
  ReadEvents: DWORD;
  hIn: THandle;
begin
  Result := #0;
  hIn := GetStdHandle(STD_INPUT_HANDLE);

  while ReadConsoleInput(hIn, Buf, 1, ReadEvents) and (ReadEvents > 0) do
  begin
    if (Buf.EventType = KEY_EVENT) and Buf.Event.KeyEvent.bKeyDown then
    begin
      Result := Buf.Event.KeyEvent.AsciiChar;
      Break;
    end;
  end;
end;
{$ENDIF}

function ReadPublicKeyFile(const FilePath: string; out KeyContent: string): boolean;
var
  SL: TStringList;
begin
  Result := False;
  KeyContent := '';
  if not FileExists(FilePath) then Exit;

  SL := TStringList.Create;
  try
    SL.LoadFromFile(FilePath);
    if SL.Count > 0 then
    begin
      KeyContent := Trim(SL[0]);
      Result := KeyContent <> '';
    end;
  except
    Result := False;
  end;
  FreeAndNil(SL);
end;

function TNETCommand.Execute: integer;
var
  TmpLogMsg, TargetIP, DevicePass, KeyPath, SSHPublicKey: string;
  BBs: TBBInterfaceList;
  xNet: TMainNet;
  Ch: char;
  Log: TLogManager;
  PromptShown: boolean;
begin
  Result := 0;
  PromptShown := False;
  Stop := False; // Скидаємо прапорець перед виконанням

  {$IFDEF UNIX}
  fpSignal(SIGINT, @HandleSigInt);
  {$ENDIF}

  {$IFDEF MSWINDOWS}
  SetConsoleCtrlHandler(@ConsoleHandler, True);
  {$ENDIF}

  BBs := GetBlackBerryInterfaces;
  if Length(BBs) = 0 then
  begin
    TConsole.WriteLn('Blackberry phone not found', ccRed);
    Exit(1);
  end;

  GetParameterValue('--ip', TargetIP);
  GetParameterValue('--password', DevicePass);
  GetParameterValue('--sshPublicKey', KeyPath);

  KeyPath := ExpandFileName(KeyPath);
  if not ReadPublicKeyFile(KeyPath, SSHPublicKey) then
  begin
    TConsole.WriteLn('Can''t read SSH public key file or file is empty: ' + KeyPath, ccRed);
    Exit(2);
  end;

  TargetIP := Trim(TargetIP);
  if TargetIP = '' then
    TargetIP := BBs[0].IPv4Phone;

  Log := TLogManager.Create;
  try
    xNet := TMainNet.Create(Log);
    try
      xNet.IP := TargetIP;
      xNet.Password := DevicePass;
      xNet.SSHKey := SSHPublicKey;

      xNet.Init;

      while (xNet.Detail <> DISCONNECTED) and (not Stop) do
      begin
        Sleep(50);

        // Виведення логів
        while Log.GetMessage(TmpLogMsg) do
          TConsole.WriteLn(TmpLogMsg);

        if (xNet.Detail = COMPLETE) and (not PromptShown) then
        begin
          PromptShown := True;
          TConsole.WriteLn('');
          TConsole.WriteLn('Press Ctrl+C or Q to quit.', ccGreen);
        end;

        // Обробка вводу з клавіатури або виходу
        if KeyPressed then
        begin
          Ch := ReadKey;
          if Ch in [#3, 'q', 'Q'] then
          begin
            Stop := True;
            Break;
          end;
        end;
      end;

      if Stop then
      begin
        TConsole.WriteLn('Exit signal received. Terminating connection...', ccYellow);
        xNet.EndConnection;
      end;

    finally
      FreeAndNil(xNet);
    end;
  finally
    FreeAndNil(Log);
  end;
end;

initialization
  NETCommand := TNETCommand.Create('connect', 'Connect to BlackBerry device over USB/Net');
  NETCommand.AddStringParameter('-i', '--ip', 'IP of target you wish to connect with');
  NETCommand.AddStringParameter('-p', '--password', 'device password', True);
  NETCommand.AddPathParameter('-k', '--sshPublicKey',
    'Path to public key (RSA) to install on device.', True);

end.
