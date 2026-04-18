#!/bin/bash

LAZRES="/home/lc/laz4/lazarus/tools/lazres"
INPUT_DIR="loaders"
OUT_DIR="compressed"
RES_FILE="resources.res"
TMP_LIST="reslist.txt"
PAS_FILE="resmap.pas"

mkdir -p "$OUT_DIR"
rm -f "$RES_FILE" "$TMP_LIST" "$PAS_FILE"

echo "[*] Стискаю унікальні файли..."

declare -A hash_to_resname
declare -A id_to_resname
declare -A id_to_hash
res_index=0

# Компресія через LZMA
compress_file() {
    # Замініть це на бажаний компресор
    lzmapack "$1" "$2"
}

# Проходимо всі файли
for f in "$INPUT_DIR"/loader_????????-*.bin; do
    [[ -f "$f" ]] || continue
    base=$(basename "$f")
    id=${base:7:8}
    hash=$(sha256sum "$f" | cut -d' ' -f1)

    # Якщо ще не додавали цей хеш
    if [[ -z "${hash_to_resname[$hash]}" ]]; then
        resname="LDR_$res_index"
        out="$OUT_DIR/${resname}.lzma"
        echo "  - $base -> $out [$resname]"
        compress_file "$f" "$out"
        echo "$out=$resname" >> "$TMP_LIST"
        hash_to_resname[$hash]=$resname
        ((res_index++))
    fi

    id_to_resname[$id]=${hash_to_resname[$hash]}
    id_to_hash[$id]=$hash
done

# Створюємо .pas-файл
count=${#id_to_resname[@]}
echo "unit resmap;" > "$PAS_FILE"
echo >> "$PAS_FILE"
echo "interface" >> "$PAS_FILE"
echo >> "$PAS_FILE"
echo "type" >> "$PAS_FILE"
echo "  TLoaderMap = record" >> "$PAS_FILE"
echo "    ID: string;" >> "$PAS_FILE"
echo "    ResName: string;" >> "$PAS_FILE"
echo "  end;" >> "$PAS_FILE"
echo >> "$PAS_FILE"
echo "const" >> "$PAS_FILE"
echo "  LoaderMap: array[0..$((count - 1))] of TLoaderMap = (" >> "$PAS_FILE"

# Виводимо список ID у впорядкованому вигляді
first=1
sorted_ids=($(for id in "${!id_to_resname[@]}"; do echo "$id"; done | sort))
for id in "${sorted_ids[@]}"; do
    resname=${id_to_resname[$id]}
    line="    (ID: '$id'; ResName: '$resname')"
    if [ $first -eq 1 ]; then
        first=0
    else
        line="    ,$line"
    fi
    echo "$line" >> "$PAS_FILE"
done

echo "  );" >> "$PAS_FILE"
echo >> "$PAS_FILE"
echo "implementation" >> "$PAS_FILE"
echo "end." >> "$PAS_FILE"

# Створюємо .res файл через lazres
echo "[*] Створюю $RES_FILE через lazres..."
"$LAZRES" "$RES_FILE" @"$TMP_LIST"

echo "[✓] Готово:"
echo "  - Ресурс: $RES_FILE"
echo "  - Pascal-мапа: $PAS_FILE"
