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
  bytes: LongInt;
begin
  Result := (fpIOCtl(0, FIONREAD, @bytes) = 0) and (bytes > 0);
end;

function ReadKey: Char;
var
  r: LongInt;
begin
  r := fpRead(0, @Result, 1);
  if r <= 0 then Result := #0;
end;
{$ENDIF}
{$IFDEF MSWINDOWS}
function ConsoleHandler(dwCtrlType: DWORD): BOOL; stdcall;
begin
  if dwCtrlType = CTRL_C_EVENT then
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
  numEvents: DWORD;
begin
  hIn := GetStdHandle(STD_INPUT_HANDLE);
  GetNumberOfConsoleInputEvents(hIn, numEvents);
  Result := numEvents > 0;
end;

function ReadKey: char;
var
  buf: TInputRecord;
  Read: DWORD;
  hIn: THandle;
begin
  hIn := GetStdHandle(STD_INPUT_HANDLE);

  Result := #0;

  if ReadConsoleInput(hIn, buf, 1, Read) then
    if (buf.EventType = KEY_EVENT) and buf.Event.KeyEvent.bKeyDown then
      Result := buf.Event.KeyEvent.AsciiChar;
end;
{$ENDIF}


function TNETCommand.Execute: integer;
var
  tmp, ip, pass, key, sshKey: string;
  BBs: TBBInterfaceList;
  xNet: TMainNet;
  keyFile: TextFile;
  ch: char;
  Log: TLogManager;
  q: boolean = False;
begin

  BBs := GetBlackBerryInterfaces;
  if length(BBs) = 0 then
  begin
    TConsole.WriteLn('Blackberry phone not found');
    Exit(1);
  end;

  GetParameterValue('--ip', ip);
  GetParameterValue('--password', pass);
  GetParameterValue('--sshPublicKey', key);
  key := ExpandFileName(key);
  if not FileExists(key) then
  begin
    TConsole.WriteLn('ssh pubkey file does not exists', ccRed);
    Exit(1);
  end;

  // Try to read SSH public key
  try
    AssignFile(keyFile, key);
    Reset(keyFile);
    ReadLn(keyFile, sshKey);
    CloseFile(keyFile);
  except
    TConsole.WriteLn('can''t read ssh pubkey file', ccRed);
    Exit(2);
  end;

  ip := Trim(ip);
  if ip = '' then
    ip := BBs[0].IPv4Phone;

  Log := TLogManager.Create;
  try
    xNet := TMainNet.Create(Log);
    try
      xNet.IP := ip;
      xNet.Password := pass;
      xNet.SSHKey := sshKey;
      xNet.Init;
      while xNet.Detail <> DISCONNECTED do
      begin
        Sleep(50);
        while Log.GetMessage(tmp) do TConsole.WriteLn(tmp);
        if (xNet.Detail = COMPLETE) and (not q) then
        begin
          q := True;
          TConsole.writeln('');
          TConsole.writeln('Press Ctrl+C or Q to quit.');
        end;

        if KeyPressed then
        begin
          ch := ReadKey;
          if ch in [#3, 'q', 'Q'] then // #3 = Ctrl+C
          begin
            TConsole.writeln('Exit signal received.');
            xNet.EndConnection;
            Break;
          end;
        end;
      end;

    finally
      FreeAndNil(xNet);
    end;

  finally
    FreeAndNil(Log);
  end;

end;

initialization
  NETCommand := TNETCommand.Create('connect', '');
  NETCommand.AddStringParameter('-i', '--ip', 'IP of target you wish to connect with');
  NETCommand.AddStringParameter('-p', '--password', 'device password', True);
  NETCommand.AddPathParameter('-k', '--sshPublicKey',
    'Path to public key (RSA) to install on device.', True);

  {$IFDEF UNIX}
  fpSignal(SIGINT, @HandleSigInt);
  {$ENDIF}

  {$IFDEF MSWINDOWS}
  SetConsoleCtrlHandler(@ConsoleHandler, True);
  {$ENDIF}

end.
