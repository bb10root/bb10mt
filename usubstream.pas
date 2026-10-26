unit uSubStream;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

type
  TSubStream = class(TStream)
  private
    FBaseStream: TStream;
    FOffset: int64;
    FSize: int64;
    FPosition: int64;
  public
    constructor Create(ABaseStream: TStream; AOffset, ASize: int64);

    function Read(var Buffer; Count: longint): longint; override;
    function Write(const Buffer; Count: longint): longint; override;
    function Seek(const Offset: int64; Origin: TSeekOrigin): int64; override;
    function GetSize: int64; override;
    function GetPosition: int64; override;
  end;


implementation

{ ---------- Implementation ---------- }

constructor TSubStream.Create(ABaseStream: TStream; AOffset, ASize: int64);
begin
  inherited Create;
  if not Assigned(ABaseStream) then
    raise Exception.Create('Base stream cannot be nil');
  if AOffset < 0 then
    raise Exception.Create('Offset cannot be negative');
  if ASize < 0 then
    raise Exception.Create('Size cannot be negative');

  FBaseStream := ABaseStream;
  FOffset := AOffset;
  FSize := ASize;
  FPosition := 0;

  if (FOffset + FSize > FBaseStream.Size) then
    raise Exception.Create('Substream exceeds base stream size');
end;

function TSubStream.Read(var Buffer; Count: longint): longint;
begin
  if FPosition >= FSize then
    Exit(0); // кінець підпотоку

  if FPosition + Count > FSize then
    Count := FSize - FPosition;

  FBaseStream.Position := FOffset + FPosition;
  Result := FBaseStream.Read(Buffer, Count);
  Inc(FPosition, Result);
end;

function TSubStream.Write(const Buffer; Count: longint): longint;
begin
  if FPosition >= FSize then
    raise Exception.Create('Cannot write beyond substream boundary');

  if FPosition + Count > FSize then
    Count := FSize - FPosition;

  FBaseStream.Position := FOffset + FPosition;
  Result := FBaseStream.Write(Buffer, Count);
  Inc(FPosition, Result);
end;

function TSubStream.Seek(const Offset: int64; Origin: TSeekOrigin): int64;
begin
  case Origin of
    soBeginning: FPosition := Offset;
    soCurrent: FPosition := FPosition + Offset;
    soEnd: FPosition := FSize + Offset;
  end;

  if FPosition < 0 then FPosition := 0;
  if FPosition > FSize then FPosition := FSize;

  Result := FPosition;
end;

function TSubStream.GetSize: int64;
begin
  Result := FSize;
end;

function TSubStream.GetPosition: int64;
begin
  Result := FPosition;
end;


end.
