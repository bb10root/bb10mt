unit qnx6.triecache;

{$mode ObjFPC}{$H+}
{$O+}

interface

uses
  SysUtils;

type
  PPathTrieNode = ^TPathTrieNode;

  TChildEntry = record
    Name: string;
    Node: PPathTrieNode;
  end;

  TPathTrieNode = record
    Inode: DWord;
    ChildCount: integer;

    // Інформація про батька дозволяє виконувати pruning в Remove()
    // без виділення стека шляху чи використання рекурсії.
    Parent: PPathTrieNode;
    ParentIndex: integer;

    // Free-list для повторного використання вузлів
    NextFree: PPathTrieNode;

    // Length(Children) = Ємність (capacity), ChildCount = реальна кількість.
    Children: array of TChildEntry;
  end;

  PChunkBlock = ^TChunkBlock;

  TChunkBlock = record
    Nodes: array[0..1023] of TPathTrieNode;
    Next: PChunkBlock;
  end;

  { TPathTrieCache }

  TPathTrieCache = class
  private
    fRoot: PPathTrieNode;

    // Chunk allocator
    fChunkHead: PChunkBlock;
    fChunkIdx: integer;

    // Вузли для повторного використання
    fFreeList: PPathTrieNode;

    function NewNode(AParent: PPathTrieNode; AParentIndex: integer): PPathTrieNode;

    procedure RecycleNode(ANode: PPathTrieNode);

    procedure RecycleSubtree(ANode: PPathTrieNode);

    procedure FreeAllChunks;

    function FindChild(ANode: PPathTrieNode; ASegment: pchar;
      ASegmentLen: integer; out AIndex: integer): boolean; inline;

    function AddChild(ANode: PPathTrieNode; ASegment: pchar;
      ASegmentLen: integer; AIndex: integer): PPathTrieNode;

    procedure DeleteChild(ANode: PPathTrieNode; AIndex: integer);

    class procedure NormalizeRange(const APath: string; out AStart, AEnd: pchar);
      static; inline;

    class function NextSegment(var P: pchar; AEnd: pchar; out ASegStart: pchar;
      out ASegLen: integer): boolean; static; inline;
  public
    constructor Create;
    destructor Destroy; override;

    procedure Clear;

    procedure AddOrSetValue(const APath: string; AInode: DWord);

    function TryGetValue(const APath: string; out AInode: DWord): boolean;

    function Remove(const APath: string): boolean;

    function RemovePrefix(const APath: string): boolean;

    function TryGetLongestPrefix(const APath: string; out AFoundPath: string;
      out AInode: DWord): boolean;
  end;

implementation

const
  CHUNK_SIZE = 1024;
  INITIAL_CHILD_CAPACITY = 4;

  { -------------------------------------------------------------------------- }
  { Path parsing                                                               }
  { -------------------------------------------------------------------------- }

class procedure TPathTrieCache.NormalizeRange(const APath: string;
  out AStart, AEnd: pchar);
begin
  AStart := PChar(APath);
  AEnd := AStart + Length(APath);

  while (AEnd > AStart) and ((AEnd - 1)^ = '/') do
    Dec(AEnd);
end;

class function TPathTrieCache.NextSegment(var P: pchar; AEnd: pchar;
  out ASegStart: pchar; out ASegLen: integer): boolean;
begin
  while (P < AEnd) and (P^ = '/') do
    Inc(P);

  if P >= AEnd then
    Exit(False);

  ASegStart := P;

  while (P < AEnd) and (P^ <> '/') do
    Inc(P);

  ASegLen := P - ASegStart;

  Result := True;
end;

{ -------------------------------------------------------------------------- }
{ Node allocator                                                             }
{ -------------------------------------------------------------------------- }

function TPathTrieCache.NewNode(AParent: PPathTrieNode;
  AParentIndex: integer): PPathTrieNode;
var
  NewChunk: PChunkBlock;
begin
  if fFreeList <> nil then
  begin
    Result := fFreeList;
    fFreeList := Result^.NextFree;

    Result^.Inode := 0;
    Result^.ChildCount := 0;
    Result^.Parent := AParent;
    Result^.ParentIndex := AParentIndex;
    Result^.NextFree := nil;

    SetLength(Result^.Children, 0);
    Exit;
  end;

  if (fChunkHead = nil) or (fChunkIdx >= CHUNK_SIZE) then
  begin
    New(NewChunk);
    NewChunk^.Next := fChunkHead;
    fChunkHead := NewChunk;
    fChunkIdx := 0;
  end;

  Result := @fChunkHead^.Nodes[fChunkIdx];
  Inc(fChunkIdx);

  Result^.Inode := 0;
  Result^.ChildCount := 0;
  Result^.Parent := AParent;
  Result^.ParentIndex := AParentIndex;
  Result^.NextFree := nil;

  Pointer(Result^.Children) := nil;
end;

procedure TPathTrieCache.RecycleNode(ANode: PPathTrieNode);
begin
  if ANode = nil then
    Exit;

  ANode^.Inode := 0;
  ANode^.ChildCount := 0;
  ANode^.Parent := nil;
  ANode^.ParentIndex := -1;

  ANode^.NextFree := fFreeList;
  fFreeList := ANode;
end;

procedure TPathTrieCache.RecycleSubtree(ANode: PPathTrieNode);
var
  I: integer;
  Child: PPathTrieNode;
begin
  if ANode = nil then
    Exit;

  for I := 0 to ANode^.ChildCount - 1 do
  begin
    Child := ANode^.Children[I].Node;
    RecycleSubtree(Child);
  end;

  for I := 0 to ANode^.ChildCount - 1 do
  begin
    ANode^.Children[I].Name := '';
    ANode^.Children[I].Node := nil;
  end;

  SetLength(ANode^.Children, 0);

  ANode^.ChildCount := 0;
  ANode^.Inode := 0;
  ANode^.Parent := nil;
  ANode^.ParentIndex := -1;

  ANode^.NextFree := fFreeList;
  fFreeList := ANode;
end;

procedure TPathTrieCache.FreeAllChunks;
var
  Curr, NextBlock: PChunkBlock;
begin
  Curr := fChunkHead;

  while Curr <> nil do
  begin
    NextBlock := Curr^.Next;
    Dispose(Curr);
    Curr := NextBlock;
  end;

  fChunkHead := nil;
  fChunkIdx := 0;
  fFreeList := nil;
end;

{ -------------------------------------------------------------------------- }
{ Child lookup (Lexicographical Binary Search)                               }
{ -------------------------------------------------------------------------- }

function TPathTrieCache.FindChild(ANode: PPathTrieNode; ASegment: pchar;
  ASegmentLen: integer; out AIndex: integer): boolean;
var
  L, H, M: integer;
  NameLen, MinLen, Cmp: integer;
  NamePtr: pchar;
begin
  L := 0;
  H := ANode^.ChildCount - 1;

  while L <= H do
  begin
    M := (L + H) shr 1;

    NamePtr := Pointer(ANode^.Children[M].Name);
    NameLen := Length(ANode^.Children[M].Name);

    if NameLen < ASegmentLen then
      MinLen := NameLen
    else
      MinLen := ASegmentLen;

    // Порівняння байтів спільної довжини
    Cmp := CompareMemRange(NamePtr, ASegment, MinLen);

    if Cmp = 0 then
    begin
      // Якщо префікси збігаються, коротший рядок вважається меншим
      if NameLen < ASegmentLen then
        Cmp := -1
      else if NameLen > ASegmentLen then
        Cmp := 1
      else
      begin
        AIndex := M;
        Exit(True);
      end;
    end;

    if Cmp < 0 then
      L := M + 1
    else
      H := M - 1;
  end;

  AIndex := L;
  Result := False;
end;

{ -------------------------------------------------------------------------- }
{ Add child                                                                  }
{ -------------------------------------------------------------------------- }

function TPathTrieCache.AddChild(ANode: PPathTrieNode; ASegment: pchar;
  ASegmentLen: integer; AIndex: integer): PPathTrieNode;
var
  Count: integer;
  Capacity: integer;
  NewCapacity: integer;
  I: integer;
begin
  Count := ANode^.ChildCount;
  Capacity := Length(ANode^.Children);

  if Count = Capacity then
  begin
    if Capacity = 0 then
      NewCapacity := INITIAL_CHILD_CAPACITY
    else
      NewCapacity := Capacity shl 1;

    SetLength(ANode^.Children, NewCapacity);
  end;

  for I := Count downto AIndex + 1 do
  begin
    ANode^.Children[I] := ANode^.Children[I - 1];
    ANode^.Children[I].Node^.ParentIndex := I;
  end;

  Result := NewNode(ANode, AIndex);

  SetString(
    ANode^.Children[AIndex].Name,
    ASegment,
    ASegmentLen);

  ANode^.Children[AIndex].Node := Result;

  Inc(ANode^.ChildCount);
end;

{ -------------------------------------------------------------------------- }
{ Delete child                                                               }
{ -------------------------------------------------------------------------- }

procedure TPathTrieCache.DeleteChild(ANode: PPathTrieNode; AIndex: integer);
var
  I: integer;
  Last: integer;
begin
  if ANode^.ChildCount <= 0 then
    Exit;

  Last := ANode^.ChildCount - 1;

  if (AIndex < 0) or (AIndex > Last) then
    Exit;

  for I := AIndex to Last - 1 do
  begin
    ANode^.Children[I] := ANode^.Children[I + 1];
    ANode^.Children[I].Node^.ParentIndex := I;
  end;

  ANode^.Children[Last].Name := '';
  ANode^.Children[Last].Node := nil;

  Dec(ANode^.ChildCount);
end;

{ -------------------------------------------------------------------------- }
{ Constructor / destructor                                                    }
{ -------------------------------------------------------------------------- }

constructor TPathTrieCache.Create;
begin
  inherited Create;

  fRoot := nil;
  fChunkHead := nil;
  fChunkIdx := 0;
  fFreeList := nil;

  fRoot := NewNode(nil, -1);
  fRoot^.Inode := 1;
end;

destructor TPathTrieCache.Destroy;
begin
  FreeAllChunks;
  fRoot := nil;
  inherited Destroy;
end;

{ -------------------------------------------------------------------------- }
{ Clear                                                                      }
{ -------------------------------------------------------------------------- }

procedure TPathTrieCache.Clear;
begin
  if fRoot = nil then
    Exit;

  FreeAllChunks;

  fRoot := NewNode(nil, -1);
  fRoot^.Inode := 1;
end;

{ -------------------------------------------------------------------------- }
{ Add / Set value                                                             }
{ -------------------------------------------------------------------------- }

procedure TPathTrieCache.AddOrSetValue(const APath: string; AInode: DWord);
var
  P, PEnd: pchar;
  SegStart: pchar;
  SegLen: integer;
  Curr, NextNode: PPathTrieNode;
  Index: integer;
begin
  if (APath = '') or (fRoot = nil) then
    Exit;

  NormalizeRange(APath, P, PEnd);

  Curr := fRoot;

  while NextSegment(P, PEnd, SegStart, SegLen) do
  begin
    if FindChild(Curr, SegStart, SegLen, Index) then
    begin
      NextNode := Curr^.Children[Index].Node;
    end
    else
    begin
      NextNode := AddChild(Curr, SegStart, SegLen, Index);
    end;

    Curr := NextNode;
  end;

  Curr^.Inode := AInode;
end;

{ -------------------------------------------------------------------------- }
{ Exact lookup                                                               }
{ -------------------------------------------------------------------------- }

function TPathTrieCache.TryGetValue(const APath: string; out AInode: DWord): boolean;
var
  P, PEnd: pchar;
  SegStart: pchar;
  SegLen: integer;
  Curr: PPathTrieNode;
  Index: integer;
begin
  AInode := 0;

  if (APath = '') or (fRoot = nil) then
    Exit(False);

  NormalizeRange(APath, P, PEnd);

  Curr := fRoot;

  while NextSegment(P, PEnd, SegStart, SegLen) do
  begin
    if not FindChild(Curr, SegStart, SegLen, Index) then
      Exit(False);

    Curr := Curr^.Children[Index].Node;
  end;

  AInode := Curr^.Inode;
  Result := AInode <> 0;
end;

{ -------------------------------------------------------------------------- }
{ Remove exact path                                                          }
{ -------------------------------------------------------------------------- }

function TPathTrieCache.Remove(const APath: string): boolean;
var
  P, PEnd: pchar;
  SegStart: pchar;
  SegLen: integer;
  Curr: PPathTrieNode;
  Index: integer;
  Target: PPathTrieNode;
  Parent: PPathTrieNode;
begin
  Result := False;

  if (APath = '') or (fRoot = nil) then
    Exit;

  NormalizeRange(APath, P, PEnd);

  if P >= PEnd then
    Exit;

  Curr := fRoot;
  Target := nil;

  while NextSegment(P, PEnd, SegStart, SegLen) do
  begin
    if not FindChild(Curr, SegStart, SegLen, Index) then
      Exit;

    Curr := Curr^.Children[Index].Node;
  end;

  Target := Curr;

  if Target^.Inode = 0 then
    Exit;

  Target^.Inode := 0;
  Result := True;

  if Target^.ChildCount <> 0 then
    Exit;

  // Ітеративний pruning знизу вгору за допомогою Parent / ParentIndex
  Curr := Target;

  while (Curr <> fRoot) and (Curr^.Inode = 0) and (Curr^.ChildCount = 0) do
  begin
    Parent := Curr^.Parent;
    Index := Curr^.ParentIndex;

    DeleteChild(Parent, Index);
    RecycleNode(Curr);

    Curr := Parent;
  end;
end;

{ -------------------------------------------------------------------------- }
{ Remove subtree                                                             }
{ -------------------------------------------------------------------------- }

function TPathTrieCache.RemovePrefix(const APath: string): boolean;
var
  P, PEnd: pchar;
  SegStart: pchar;
  SegLen: integer;
  Curr: PPathTrieNode;
  Parent: PPathTrieNode;
  Index: integer;
begin
  Result := False;

  if fRoot = nil then
    Exit;

  if APath = '' then
  begin
    Clear;
    Exit(True);
  end;

  NormalizeRange(APath, P, PEnd);

  Curr := fRoot;
  Parent := nil;
  Index := -1;

  while NextSegment(P, PEnd, SegStart, SegLen) do
  begin
    if not FindChild(Curr, SegStart, SegLen, Index) then
      Exit;

    Parent := Curr;
    Curr := Curr^.Children[Index].Node;
  end;

  if (Parent = nil) or (Index < 0) then
    Exit;

  RecycleSubtree(Curr);
  DeleteChild(Parent, Index);

  Result := True;
end;

{ -------------------------------------------------------------------------- }
{ Longest prefix                                                             }
{ -------------------------------------------------------------------------- }

function TPathTrieCache.TryGetLongestPrefix(const APath: string;
  out AFoundPath: string; out AInode: DWord): boolean;
var
  P, PEnd: pchar;
  SegStart: pchar;
  SegLen: integer;
  Curr: PPathTrieNode;
  NextNode: PPathTrieNode;
  Index: integer;
  LastMatch: pchar;
begin
  AFoundPath := '';
  AInode := 0;

  if fRoot = nil then
    Exit(False);

  if fRoot^.Inode <> 0 then
  begin
    AInode := fRoot^.Inode;
    AFoundPath := '/';
  end;

  if APath = '' then
    Exit(AInode <> 0);

  NormalizeRange(APath, P, PEnd);

  Curr := fRoot;
  LastMatch := nil;

  while NextSegment(P, PEnd, SegStart, SegLen) do
  begin
    if not FindChild(Curr, SegStart, SegLen, Index) then
      Break;

    NextNode := Curr^.Children[Index].Node;

    if NextNode^.Inode <> 0 then
    begin
      AInode := NextNode^.Inode;
      LastMatch := P;
    end;

    Curr := NextNode;
  end;

  if AInode = 0 then
    Exit(False);

  if LastMatch = nil then
  begin
    AFoundPath := '/';
  end
  else
  begin
    SetString(
      AFoundPath,
      PChar(APath),
      LastMatch - PChar(APath));
  end;

  Result := True;
end;

end.
