unit bits;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

const
  BITSHIFT = 5;
  MASK = 31; {for longs that are 32-bit in size}
  {$ifdef cpu16}
   MaxBitFlags = $7FE0;
  {$else cpu16}
  MaxBitFlags = $7FFFFFE0;
  {$endif cpu16}
  MaxBitRec = MaxBitFlags div (SizeOf(cardinal) * 8);

resourcestring
  SErrIndexTooLarge = 'Bit index exceeds array limit: %d';
  SErrInvalidBitIndex = 'Invalid bit index : %d';
  SErrOutOfMemory = 'Out of memory';

type
  EBitsError = class(Exception);

  TBitArray = array[0..MaxBitRec - 1] of cardinal;
  PBitArray = ^TBitArray;

  XBits = class(TObject)
  private
    FBits: PBitArray;
    FSize: longint;     // total cardinals currently allocated
    FBSize: longint;    // total bits currently allocated
    FFindIndex: longint; // renamed for consistency
    FFindState: boolean; // renamed for consistency

    procedure SetBit(Bit: longint; Value: boolean);
    procedure SetSize(Value: longint);
    function GetFBitsPtr: Pointer;
    procedure CheckBitIndex(Bit: longint; CurrentSize: boolean);

  public
    constructor Create(TheSize: longint = 0);
    destructor Destroy; override;

    // Basic bit operations
    procedure SetOn(Bit: longint);
    procedure Clear(Bit: longint);
    procedure ClearAll;
    function Get(Bit: longint): boolean;
    procedure Grow(NBit: longint);

    // Bit array operations
    procedure CopyBits(BitSet: XBits);
    procedure AndBits(BitSet: XBits);
    procedure OrBits(BitSet: XBits);
    procedure XorBits(BitSet: XBits);
    procedure NotXorBits(BitSet: XBits); // renamed from NoXBits for clarity

    // Comparison
    function Equals(Obj: TObject): boolean; override; overload;
    function Equals(BitSet: XBits): boolean; overload;

    // Search operations
    procedure SetIndex(Index: longint);
    function FindFirstBit(State: boolean): longint;
    function FindNextBit: longint;
    function FindPrevBit: longint;
    function OpenBit: longint;

    // Properties
    property Bits[Bit: longint]: boolean read Get write SetBit; default;
    property Size: longint read FBSize write SetSize;
    property BitsPtr: Pointer read GetFBitsPtr;
    property AllocatedSize: longint read FSize; // expose internal size
  end;

implementation

// Lookup table for bit operations - using const for better performance
const
  BitMasks: array[0..31] of cardinal = (
    $00000001, $00000002, $00000004, $00000008,
    $00000010, $00000020, $00000040, $00000080,
    $00000100, $00000200, $00000400, $00000800,
    $00001000, $00002000, $00004000, $00008000,
    $00010000, $00020000, $00040000, $00080000,
    $00100000, $00200000, $00400000, $00800000,
    $01000000, $02000000, $04000000, $08000000,
    $10000000, $20000000, $40000000, $80000000
  );

procedure BitsError(const Msg: string);
begin
  raise EBitsError.Create(Msg);
end;

procedure BitsErrorFmt(const Msg: string; const Args: array of const);
begin
  raise EBitsError.CreateFmt(Msg, Args);
end;

{Min function for Longint - inline for performance}
function Min(X, Y: longint): longint; inline;
begin
  if X < Y then
    Result := X
  else
    Result := Y;
end;

{Max function for Longint - inline for performance}
function Max(X, Y: longint): longint; inline;
begin
  if X > Y then
    Result := X
  else
    Result := Y;
end;

{ XBits Implementation }

constructor XBits.Create(TheSize: longint = 0);
begin
  inherited Create;
  FSize := 0;
  FBSize := 0;
  FBits := nil;
  FFindIndex := -1;
  FFindState := False;
  if TheSize > 0 then
    Grow(TheSize);
end;

destructor XBits.Destroy;
begin
  if FBits <> nil then
  begin
    FreeMem(FBits);
    FBits := nil;
  end;
  inherited Destroy;
end;

procedure XBits.CheckBitIndex(Bit: longint; CurrentSize: boolean);
begin
  if Bit < 0 then
    BitsErrorFmt(SErrInvalidBitIndex, [Bit]);
  if CurrentSize and (Bit >= FBSize) then
    BitsErrorFmt(SErrInvalidBitIndex, [Bit]);
  if Bit >= MaxBitFlags then
    BitsErrorFmt(SErrIndexTooLarge, [Bit]);
end;

function XBits.GetFBitsPtr: Pointer;
begin
  Result := FBits;
end;

procedure XBits.SetSize(Value: longint);
var
  NewSize, OldSize: longint;
  I: longint;
begin
  CheckBitIndex(Value, False);

  if Value <> 0 then
    NewSize := (Value + MASK) shr BITSHIFT // Fixed: proper ceiling division
  else
    NewSize := 0;

  if NewSize <> FSize then
  begin
    OldSize := FSize;
    ReallocMem(FBits, NewSize * SizeOf(cardinal));

    if (FBits = nil) and (NewSize > 0) then
      BitsError(SErrOutOfMemory);

    FSize := NewSize;

    // Initialize new memory to zero
    if NewSize > OldSize then
    begin
      for I := OldSize to NewSize - 1 do
        FBits^[I] := 0;
    end;
  end;
  FBSize := Value;
end;

procedure XBits.SetBit(Bit: longint; Value: boolean);
var
  WordIndex: longint;
  BitIndex: longint;
begin
  Grow(Bit + 1);
  WordIndex := Bit shr BITSHIFT;
  BitIndex := Bit and MASK;

  if Value then
    FBits^[WordIndex] := FBits^[WordIndex] or BitMasks[BitIndex]
  else
    FBits^[WordIndex] := FBits^[WordIndex] and not BitMasks[BitIndex];
end;

function XBits.Get(Bit: longint): boolean;
var
  WordIndex: longint;
begin
  CheckBitIndex(Bit, True);
  WordIndex := Bit shr BITSHIFT;

  if WordIndex < FSize then
    Result := (FBits^[WordIndex] and BitMasks[Bit and MASK]) <> 0
  else
    Result := False;
end;

procedure XBits.Grow(NBit: longint);
begin
  if NBit > FBSize then
    SetSize(NBit);
end;

procedure XBits.SetOn(Bit: longint);
begin
  SetBit(Bit, True);
end;

procedure XBits.Clear(Bit: longint);
begin
  SetBit(Bit, False);
end;

procedure XBits.ClearAll;
begin
  if FBits <> nil then
    FillChar(FBits^, FSize * SizeOf(cardinal), 0); // More efficient than loop
end;

function XBits.OpenBit: longint;
var
  WordIndex, BitIndex: longint;
  MaxWords: longint;
begin
  Result := -1;
  MaxWords := (FBSize + MASK) shr BITSHIFT;

  for WordIndex := 0 to MaxWords - 1 do
  begin
    if FBits^[WordIndex] <> $FFFFFFFF then
    begin
      for BitIndex := 0 to MASK do
      begin
        if (FBits^[WordIndex] and BitMasks[BitIndex]) = 0 then
        begin
          Result := (WordIndex shl BITSHIFT) + BitIndex;
          if Result >= FBSize then
          begin
            Result := FBSize;
            Exit;
          end;
          Exit;
        end;
      end;
    end;
  end;

  // If no open bit found and we can grow
  if FSize < MaxBitRec then
    Result := FBSize;
end;

procedure XBits.CopyBits(BitSet: XBits);
begin
  if BitSet = nil then Exit;

  SetSize(BitSet.Size);
  if (FSize > 0) and (BitSet.FSize > 0) then
    Move(BitSet.FBits^, FBits^, Min(FSize, BitSet.FSize) * SizeOf(cardinal));
end;

procedure XBits.AndBits(BitSet: XBits);
var
  MinSize, I: longint;
begin
  if BitSet = nil then
  begin
    ClearAll;
    Exit;
  end;

  MinSize := Min(FSize, BitSet.FSize);

  // AND operation on overlapping part
  for I := 0 to MinSize - 1 do
    FBits^[I] := FBits^[I] and BitSet.FBits^[I];

  // Clear remaining bits (AND with 0)
  for I := MinSize to FSize - 1 do
    FBits^[I] := 0;
end;

procedure XBits.OrBits(BitSet: XBits);
var
  I: longint;
begin
  if BitSet = nil then Exit;

  Grow(BitSet.Size);

  for I := 0 to BitSet.FSize - 1 do
    FBits^[I] := FBits^[I] or BitSet.FBits^[I];
end;

procedure XBits.XorBits(BitSet: XBits);
var
  I: longint;
begin
  if BitSet = nil then Exit;

  Grow(BitSet.Size);

  for I := 0 to BitSet.FSize - 1 do
    FBits^[I] := FBits^[I] xor BitSet.FBits^[I];
end;

procedure XBits.NotXorBits(BitSet: XBits);
var
  MinSize, I: longint;
begin
  if BitSet = nil then Exit;

  MinSize := Min(FSize, BitSet.FSize);

  for I := 0 to MinSize - 1 do
    FBits^[I] := FBits^[I] xor BitSet.FBits^[I];
end;

function XBits.Equals(Obj: TObject): boolean;
begin
  if Obj is XBits then
    Result := Equals(XBits(Obj))
  else
    Result := inherited Equals(Obj);
end;

function XBits.Equals(BitSet: XBits): boolean;
var
  MinSize, MaxSize, I: longint;
  LargerSet: XBits;
begin
  Result := False;

  if BitSet = nil then Exit;
  if Self = BitSet then
  begin
    Result := True;
    Exit;
  end;

  MinSize := Min(FSize, BitSet.FSize);
  MaxSize := Max(FSize, BitSet.FSize);

  // Compare overlapping parts
  for I := 0 to MinSize - 1 do
    if FBits^[I] <> BitSet.FBits^[I] then
      Exit;

  // Check if remaining parts of larger set are all zeros
  if FSize > BitSet.FSize then
    LargerSet := Self
  else
    LargerSet := BitSet;

  for I := MinSize to MaxSize - 1 do
    if LargerSet.FBits^[I] <> 0 then
      Exit;

  Result := True;
end;

procedure XBits.SetIndex(Index: longint);
begin
  CheckBitIndex(Index, True);
  FFindIndex := Index;
end;

function XBits.FindFirstBit(State: boolean): longint;
var
  WordIndex, BitIndex: longint;
  StartBit, StopBit: longint;
  CompareVal: cardinal;
begin
  Result := -1;
  FFindState := State;

  if State then
    CompareVal := $00000000  // looking for set bits
  else
    CompareVal := $FFFFFFFF; // looking for clear bits

  for WordIndex := 0 to FSize - 1 do
  begin
    if FBits^[WordIndex] <> CompareVal then
    begin
      StartBit := WordIndex shl BITSHIFT;
      StopBit := Min(StartBit + MASK, FBSize - 1);

      for BitIndex := StartBit to StopBit do
      begin
        if Get(BitIndex) = State then
        begin
          Result := BitIndex;
          FFindIndex := Result;
          Exit;
        end;
      end;
    end;
  end;

  FFindIndex := Result;
end;

function XBits.FindNextBit: longint;
var
  I: longint;
begin
  Result := -1;

  if FFindIndex >= 0 then
  begin
    for I := FFindIndex + 1 to FBSize - 1 do
    begin
      if Get(I) = FFindState then
      begin
        Result := I;
        Break;
      end;
    end;
    FFindIndex := Result;
  end;
end;

function XBits.FindPrevBit: longint;
var
  I: longint;
begin
  Result := -1;

  if FFindIndex >= 0 then
  begin
    for I := FFindIndex - 1 downto 0 do
    begin
      if Get(I) = FFindState then
      begin
        Result := I;
        Break;
      end;
    end;
    FFindIndex := Result;
  end;
end;

end.
