program bb10mt;
{$mode objfpc}{$H+}
{$ifdef MSWINDOWS} {$apptype CONSOLE} {$endif}
{$DEFINE FPC_X64MM}
{$DEFINE FPC_LIBCMM}
uses
  {$I mormot.uses.inc} // may include fpcx64mm or fpclibcmm
  Classes,
  SysUtils,
  CLI.Interfaces,    // Core interfaces
  CLI.Application,   // Main application framework
  CLI.Console,       // Optional: Colored console output
  uFlash,
  uQNX,
  uBar,
  uRCFS,
  uQCFM,
  uRAW,
  uNet, uBatch;

  {$R *.res}


var
  App: ICLIApplication;


begin
  App := CreateCLIApplication('BB10 MultiTool', '0.6.0.0(beta 3)');
  // Register command
  App.RegisterCommand(QNX6cmd);
  App.RegisterCommand(UnPack);
  App.RegisterCommand(Pack);
  App.RegisterCommand(Split);
  App.RegisterCommand(Flash);
  App.RegisterCommand(Info);
  App.RegisterCommand(Bar);
  App.RegisterCommand(RawCommand);
  App.RegisterCommand(Loader);
  App.RegisterCommand(Autoloader);
  App.RegisterCommand(RCFSCommand);
  App.RegisterCommand(NETCommand);
  App.RegisterCommand(Nuke);
  App.RegisterCommand(BatchCmd);


  // Execute application
  ExitCode := App.Execute;
  TConsole.ResetColors;
end.
