unit Logger;

interface

uses
  Classes, SysUtils, SyncObjs, Generics.Collections;

type
  TLogManager = class
  private
    FQueue: specialize TQueue<string>;
    FLock: TRTLCriticalSection;
  public
    constructor Create;
    destructor Destroy; override;

    procedure AddMessage(const Msg: string);
    function GetMessage(out msg: string): boolean;
    procedure FlushMessages;
  end;

implementation

constructor TLogManager.Create;
begin
  inherited Create;
  FQueue := specialize TQueue<string>.Create;
  InitCriticalSection(FLock);
end;

destructor TLogManager.Destroy;
begin
  DoneCriticalSection(FLock);
  FQueue.Free;
  inherited;
end;

procedure TLogManager.AddMessage(const Msg: string);
begin
  EnterCriticalSection(FLock);
  try
    FQueue.Enqueue(Msg);
  finally
    LeaveCriticalSection(FLock);
  end;
end;

function TLogManager.GetMessage(out msg: string): boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := FQueue.Count > 0;
    if Result then
      msg := FQueue.Dequeue
    else
      msg := '';
  finally
    LeaveCriticalSection(FLock);
  end;

end;

procedure TLogManager.FlushMessages;
var
  Msg: string;
begin
  EnterCriticalSection(FLock);
  try
    while FQueue.Count > 0 do
    begin
      Msg := FQueue.Dequeue;
      WriteLn(Msg);
      Flush(Output);
    end;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

end.
