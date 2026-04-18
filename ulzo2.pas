unit uLZO2;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

const
  LZO1X_999_MEM_COMPRESS = 14 * 16384 * 2;

  // External LZO functions
var
  __lzo_init_v2: function(ver: cardinal;
  int1, int2, int3, int4, int5, int6, int7, int8, int9: integer): integer;
  {$ifdef windows}stdcall{$else} cdecl{$endif};
  lzo_version: function(): cardinal; {$ifdef windows}stdcall{$else} cdecl{$endif};
  lzo1x_1_compress: function(src: Pointer; src_len: longword; dest: Pointer;
  var dest_len: longword; wrkmem: Pointer): integer; {$ifdef windows}stdcall{$else} cdecl{$endif};
  lzo1x_999_compress: function(src: Pointer; src_len: longword; dest: Pointer;
  var dest_len: longword; wrkmem: Pointer): integer; {$ifdef windows}stdcall{$else} cdecl{$endif};
  lzo1x_decompress_safe: function(src: Pointer; src_len: longword; dest: Pointer;
  var dest_len: longword; wrkmem: Pointer): integer; {$ifdef windows}stdcall{$else} cdecl{$endif};
  lzo1x_optimize: function(src: Pointer; src_len: longword; dest: Pointer;
  var dest_len: longword; wrkmem: Pointer): integer; {$ifdef windows}stdcall{$else} cdecl{$endif};


implementation

var
  dllHandle: TLibHandle = 0;

procedure initDLL;
var
  res, ver: cardinal;
begin
  {$IF DEFINED(WINDOWS)}
  dllHandle := LoadLibrary('lzo2.dll');
  {$ELSEIF DEFINED(DARWIN)}
  dllHandle := LoadLibrary('liblzo2.dylib');
  if dllHandle = 0 then
    dllHandle := LoadLibrary('/opt/local/lib/liblzo2.dylib');
  if dllHandle = 0 then
    dllHandle := LoadLibrary('/opt/homebrew/lib/liblzo2.dylib');
  {$ELSE}
  dllHandle := LoadLibrary('liblzo2.so');
  {$ENDIF}
  if dllHandle = 0 then
    raise Exception.Create('Couldn''t load dynamic library liblzo2.');
  pointer(lzo_version) := GetProcedureAddress(dllHandle, 'lzo_version');
  pointer(__lzo_init_v2) := GetProcedureAddress(dllHandle, '__lzo_init_v2');
  pointer(lzo1x_1_compress) := GetProcedureAddress(dllHandle, 'lzo1x_1_compress');
  pointer(lzo1x_999_compress) := GetProcedureAddress(dllHandle, 'lzo1x_999_compress');
  pointer(lzo1x_decompress_safe) := GetProcedureAddress(dllHandle, 'lzo1x_decompress_safe');
  pointer(lzo1x_optimize) := GetProcedureAddress(dllHandle, 'lzo1x_optimize');
  ver := lzo_version();
  res := __lzo_init_v2(ver, -1, -1, -1, -1, -1, -1, -1, -1, -1);
  if res <> 0 then
    raise Exception.Create('LZO initialization failed');

end;


initialization
  initDLL;

end.
