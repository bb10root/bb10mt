unit uSubStream;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;
  type
  TSubStream = class(TStream)
  private
    FBaseStream: TStream;
    FOffset: Int64;
    FSize: Int64;
    FPosition: Int64;
  public
    constructor Create(ABaseStream: TStream; AOffset, ASize: Int64);

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
    function GetSize: Int64; override;
    function GetPosition: Int64; override;
  end;


implementation

{ ---------- Implementation ---------- }

constructor TSubStream.Create(ABaseStream: TStream; AOffset, ASize: Int64);
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

function TSubStream.Read(var Buffer; Count: Longint): Longint;
begin
  if FPosition >= FSize then
    Exit(0); // кінець підпотоку

  if FPosition + Count > FSize then
    Count := FSize - FPosition;

  FBaseStream.Position := FOffset + FPosition;
  Result := FBaseStream.Read(Buffer, Count);
  Inc(FPosition, Result);
end;

function TSubStream.Write(const Buffer; Count: Longint): Longint;
begin
  if FPosition >= FSize then
    raise Exception.Create('Cannot write beyond substream boundary');

  if FPosition + Count > FSize then
    Count := FSize - FPosition;

  FBaseStream.Position := FOffset + FPosition;
  Result := FBaseStream.Write(Buffer, Count);
  Inc(FPosition, Result);
end;

function TSubStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
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

function TSubStream.GetSize: Int64;
begin
  Result := FSize;
end;

function TSubStream.GetPosition: Int64;
begin
  Result := FPosition;
end;


end.

