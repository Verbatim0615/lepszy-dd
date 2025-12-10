#!/bin/bash

clear

LOG_DIR="/var/log/dd_tool"
HISTORY_FILE="$LOG_DIR/operations_history.log"
METADATA_DIR="$LOG_DIR/metadata"

mkdir -p "$LOG_DIR"
mkdir -p "$METADATA_DIR"

OPERATION_ID=$(date +%Y%m%d_%H%M%S)_$$
OPERATION_LOG="$LOG_DIR/operation_${OPERATION_ID}.log"

function log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$OPERATION_LOG"
}

function log_to_history() {
    echo "$1" >> "$HISTORY_FILE"
}

echo "Narzędzie do klonowania DD - Wersja Professional"
echo ""
log_message "Rozpoczęcie nowej operacji - ID: $OPERATION_ID"

if [ "$EUID" -ne 0 ]; then
    echo "Ten skrypt wymaga uprawnień root"
    echo "Uruchom ponownie: sudo $0"
    exit 1
fi

function show_devices() {
    echo ""
    echo "Dostępne urządzenia w systemie:"
    echo ""
    lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL,SERIAL
    echo ""
    df -h | grep -E '^/dev/'
    echo ""
}

function check_space() {
    local src=$1
    local dst=$2
    
    if [ -b "$src" ]; then
        src_size=$(blockdev --getsize64 "$src" 2>/dev/null)
    elif [ -f "$src" ]; then
        src_size=$(stat -c%s "$src")
    else
        src_size=0
    fi
    
    if [ -b "$dst" ]; then
        dst_size=$(blockdev --getsize64 "$dst" 2>/dev/null)
        if [ $src_size -gt $dst_size ]; then
            log_message "BŁĄD: Urządzenie docelowe jest za małe"
            return 1
        fi
    else
        dst_dir=$(dirname "$dst")
        available=$(df --output=avail "$dst_dir" | tail -1)
        available_bytes=$((available * 1024))
        if [ $src_size -gt $available_bytes ]; then
            log_message "BŁĄD: Za mało miejsca na dysku docelowym"
            return 1
        fi
    fi
    
    return 0
}

function calculate_hash() {
    local file=$1
    local algorithm=$2
    local label=$3
    
    echo ""
    log_message "Obliczanie $algorithm dla $label..."
    
    case $algorithm in
        "md5")
            hash=$(md5sum "$file" 2>/dev/null | awk '{print $1}')
            ;;
        "sha1")
            hash=$(sha1sum "$file" 2>/dev/null | awk '{print $1}')
            ;;
        "sha256")
            hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            ;;
    esac
    
    echo "$algorithm: $hash"
    log_message "$label $algorithm: $hash"
    echo "$hash"
}

function verify_integrity() {
    local src=$1
    local dst=$2
    local algorithms=("md5" "sha1" "sha256")
    
    echo ""
    log_message "Rozpoczęcie weryfikacji integralności"
    echo "Weryfikacja integralności danych..."
    echo ""
    
    local all_match=true
    
    for algo in "${algorithms[@]}"; do
        src_hash=$(calculate_hash "$src" "$algo" "źródło")
        dst_hash=$(calculate_hash "$dst" "$algo" "cel")
        
        if [ "$src_hash" == "$dst_hash" ]; then
            echo "OK - $algo pasuje"
            log_message "Weryfikacja $algo: SUKCES"
        else
            echo "BŁĄD - $algo NIE pasuje"
            log_message "Weryfikacja $algo: NIEPOWODZENIE"
            all_match=false
        fi
    done
    
    echo ""
    if $all_match; then
        log_message "Weryfikacja integralności: SUKCES - wszystkie sumy się zgadzają"
        return 0
    else
        log_message "Weryfikacja integralności: NIEPOWODZENIE"
        return 1
    fi
}

function create_metadata() {
    local src=$1
    local dst=$2
    local metadata_file="$METADATA_DIR/metadata_${OPERATION_ID}.txt"
    
    log_message "Tworzenie pliku metadanych"
    
    {
        echo "=================================================="
        echo "METADATA OPERACJI DD"
        echo "=================================================="
        echo "ID Operacji: $OPERATION_ID"
        echo "Data: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Użytkownik: $(whoami)"
        echo "Hostname: $(hostname)"
        echo ""
        echo "ŹRÓDŁO:"
        echo "  Ścieżka: $src"
        if [ -b "$src" ]; then
            echo "  Typ: Urządzenie blokowe"
            echo "  Rozmiar: $(blockdev --getsize64 "$src" 2>/dev/null) bajtów"
            echo "  Model: $(lsblk -ndo MODEL "$src" 2>/dev/null || echo 'N/A')"
            echo "  Serial: $(lsblk -ndo SERIAL "$src" 2>/dev/null || echo 'N/A')"
        else
            echo "  Typ: Plik"
            echo "  Rozmiar: $(stat -c%s "$src") bajtów"
        fi
        echo ""
        echo "CEL:"
        echo "  Ścieżka: $dst"
        echo ""
        echo "PARAMETRY:"
        echo "  Rozmiar bloku: $block_size"
        echo "  Kompresja: $use_compression"
        echo "  Split: $use_split"
        if [ "$use_split" == "tak" ]; then
            echo "  Rozmiar części: $split_size"
        fi
        echo ""
        echo "=================================================="
    } > "$metadata_file"
    
    echo "Plik metadanych: $metadata_file"
    log_message "Utworzono plik metadanych: $metadata_file"
}

function show_history() {
    if [ -f "$HISTORY_FILE" ]; then
        echo ""
        echo "Ostatnie 10 operacji:"
        echo ""
        tail -10 "$HISTORY_FILE"
        echo ""
    fi
}

function export_forensic_report() {
    local report_file="$METADATA_DIR/forensic_report_${OPERATION_ID}.txt"
    
    log_message "Generowanie raportu forensic"
    
    {
        echo "=================================================="
        echo "RAPORT FORENSIC - IMAGING DYSKU"
        echo "=================================================="
        echo ""
        echo "1. INFORMACJE PODSTAWOWE"
        echo "   ID Operacji: $OPERATION_ID"
        echo "   Data rozpoczęcia: $start_date"
        echo "   Data zakończenia: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "   Czas trwania: ${elapsed}s"
        echo "   Operator: $(whoami)"
        echo ""
        echo "2. URZĄDZENIE ŹRÓDŁOWE"
        echo "   Ścieżka: $source_path"
        echo "   Rozmiar: $source_size_human"
        echo ""
        echo "3. URZĄDZENIE DOCELOWE"
        echo "   Ścieżka: $dest_path"
        echo ""
        echo "4. PARAMETRY OPERACJI"
        echo "   Metoda: dd"
        echo "   Rozmiar bloku: $block_size"
        echo "   Opcje conv: noerror,sync"
        echo ""
        echo "5. SUMY KONTROLNE"
        grep -E "(md5|sha1|sha256)" "$OPERATION_LOG"
        echo ""
        echo "6. STATUS"
        echo "   Kod wyjścia DD: $dd_exit_code"
        echo "   Status: $([ $dd_exit_code -eq 0 ] && echo 'SUKCES' || echo 'BŁĄD')"
        echo ""
        echo "=================================================="
        echo "Raport wygenerowany automatycznie"
        echo "Plik logu: $OPERATION_LOG"
        echo "=================================================="
    } > "$report_file"
    
    echo ""
    echo "Raport forensic zapisany: $report_file"
    log_message "Wygenerowano raport forensic: $report_file"
}

show_devices

read -p "Pokazać historię ostatnich operacji? [t/N]: " show_hist
if [[ "$show_hist" =~ ^[Tt]$ ]]; then
    show_history
fi

echo ""
echo "Wybór źródła"
read -p "Podaj ścieżkę źródłową: " source_path

if [ ! -e "$source_path" ]; then
    echo "Błąd: Źródło nie istnieje"
    log_message "BŁĄD: Źródło nie istnieje - $source_path"
    exit 1
fi

log_message "Źródło: $source_path"

if [ -b "$source_path" ]; then
    source_size=$(blockdev --getsize64 "$source_path" 2>/dev/null)
    source_size_human=$(numfmt --to=iec-i --suffix=B $source_size 2>/dev/null || echo "unknown")
    echo "Urządzenie blokowe: $source_size_human"
    log_message "Typ źródła: Urządzenie blokowe, rozmiar: $source_size_human"
elif [ -f "$source_path" ]; then
    source_size=$(stat -c%s "$source_path")
    source_size_human=$(numfmt --to=iec-i --suffix=B $source_size 2>/dev/null || echo "unknown")
    echo "Plik: $source_size_human"
    log_message "Typ źródła: Plik, rozmiar: $source_size_human"
fi

echo ""
echo "Wybór celu"
read -p "Podaj ścieżkę docelową: " dest_path
log_message "Cel: $dest_path"

if mount | grep -q "^$dest_path"; then
    echo "Urządzenie $dest_path jest zamontowane"
    mount | grep "^$dest_path"
    log_message "UWAGA: Urządzenie docelowe zamontowane"
    echo ""
    read -p "Odmontować automatycznie? [t/N]: " do_unmount
    if [[ "$do_unmount" =~ ^[Tt]$ ]]; then
        umount "$dest_path"* 2>/dev/null
        sleep 1
        if mount | grep -q "^$dest_path"; then
            echo "Nie udało się odmontować"
            log_message "BŁĄD: Odmontowanie nieudane"
            exit 1
        fi
        echo "Odmontowano"
        log_message "Odmontowano urządzenie docelowe"
    else
        echo "Operacja anulowana"
        log_message "Operacja anulowana przez użytkownika - odmontowanie"
        exit 1
    fi
fi

echo ""
echo "Sprawdzanie przestrzeni"
check_space "$source_path" "$dest_path"

echo ""
echo "Zaawansowane opcje"
echo ""

read -p "Użyć kompresji podczas kopiowania? [t/N]: " compress_choice
if [[ "$compress_choice" =~ ^[Tt]$ ]]; then
    use_compression="tak"
    echo "Dostępne algorytmy kompresji:"
    echo "  1. gzip (szybki)"
    echo "  2. bzip2 (lepszy stosunek)"
    echo "  3. xz (najlepszy stosunek, wolniejszy)"
    read -p "Wybierz [1]: " compress_algo
    compress_algo=${compress_algo:-1}
    case $compress_algo in
        1) compress_cmd="gzip" ;;
        2) compress_cmd="bzip2" ;;
        3) compress_cmd="xz" ;;
        *) compress_cmd="gzip" ;;
    esac
    dest_path="${dest_path}.${compress_cmd}"
    log_message "Kompresja włączona: $compress_cmd"
else
    use_compression="nie"
    log_message "Kompresja wyłączona"
fi

echo ""
read -p "Podzielić obraz na mniejsze części? [t/N]: " split_choice
if [[ "$split_choice" =~ ^[Tt]$ ]]; then
    use_split="tak"
    echo "Dostępne rozmiary części:"
    echo "  1. 1GB"
    echo "  2. 2GB"
    echo "  3. 4GB"
    echo "  4. 10GB"
    echo "  5. Niestandardowy"
    read -p "Wybierz [3]: " split_option
    split_option=${split_option:-3}
    case $split_option in
        1) split_size="1G" ;;
        2) split_size="2G" ;;
        3) split_size="4G" ;;
        4) split_size="10G" ;;
        5) 
            read -p "Podaj rozmiar (np. 500M, 5G): " split_size
            ;;
        *) split_size="4G" ;;
    esac
    log_message "Split włączony: $split_size"
else
    use_split="nie"
    log_message "Split wyłączony"
fi

echo ""
read -p "Utworzyć dodatkową kopię bezpieczeństwa jednocześnie? [t/N]: " backup_choice
if [[ "$backup_choice" =~ ^[Tt]$ ]]; then
    read -p "Podaj ścieżkę dla kopii zapasowej: " backup_path
    use_backup="tak"
    log_message "Backup włączony: $backup_path"
else
    use_backup="nie"
    log_message "Backup wyłączony"
fi

echo ""
echo "Parametry operacji"
echo ""
echo "Dostępne rozmiary bloków:"
echo "  1. 512K  - wolniejszy, bezpieczniejszy"
echo "  2. 1M    - standardowy"
echo "  3. 4M    - zalecany"
echo "  4. 8M    - szybszy"
echo "  5. 16M   - bardzo szybki, większe ryzyko"
echo ""
read -p "Wybierz opcję [3]: " bs_choice
bs_choice=${bs_choice:-3}

case $bs_choice in
    1) block_size="512K" ;;
    2) block_size="1M" ;;
    3) block_size="4M" ;;
    4) block_size="8M" ;;
    5) block_size="16M" ;;
    *) block_size="4M" ;;
esac
log_message "Rozmiar bloku: $block_size"

echo ""
read -p "Przeprowadzić pełną weryfikację integralności (MD5/SHA1/SHA256)? [T/n]: " do_verify
do_verify=${do_verify:-T}
log_message "Weryfikacja integralności: $([ "$do_verify" == 'T' ] || [ "$do_verify" == 't' ] && echo 'włączona' || echo 'wyłączona')"

echo ""
read -p "Wykonać synchronizację po zakończeniu? [T/n]: " do_sync
do_sync=${do_sync:-T}
log_message "Synchronizacja: $([ "$do_sync" == 'T' ] || [ "$do_sync" == 't' ] && echo 'włączona' || echo 'wyłączona')"

echo ""
read -p "Wygenerować raport forensic? [T/n]: " do_forensic
do_forensic=${do_forensic:-T}
log_message "Raport forensic: $([ "$do_forensic" == 'T' ] || [ "$do_forensic" == 't' ] && echo 'włączony' || echo 'wyłączony')"

create_metadata "$source_path" "$dest_path"

echo ""
echo "=================================================="
echo "PODSUMOWANIE OPERACJI"
echo "=================================================="
echo "ID Operacji: $OPERATION_ID"
echo "Źródło:  $source_path"
echo "Cel:     $dest_path"
echo "Blok:    $block_size"
echo "Rozmiar: $source_size_human"
if [ "$use_compression" == "tak" ]; then
    echo "Kompresja: $compress_cmd"
fi
if [ "$use_split" == "tak" ]; then
    echo "Split: $split_size"
fi
if [ "$use_backup" == "tak" ]; then
    echo "Backup: $backup_path"
fi
echo "=================================================="
echo ""
echo "OSTRZEŻENIE:"
echo "Wszystkie dane na urządzeniu docelowym"
echo "zostaną BEZPOWROTNIE UTRACONE i NADPISANE"
echo ""
echo "Logi zapisywane do: $OPERATION_LOG"
echo ""
read -p "Aby kontynuować wpisz: WYKONAJ > " final_confirm

if [ "$final_confirm" != "WYKONAJ" ]; then
    echo ""
    echo "Operacja została anulowana przez użytkownika"
    log_message "Operacja anulowana przez użytkownika - brak potwierdzenia"
    exit 0
fi

start_date=$(date '+%Y-%m-%d %H:%M:%S')

echo ""
echo "=================================================="
log_message "Rozpoczęcie kopiowania"
echo "Rozpoczynam klonowanie..."
echo "Czas rozpoczęcia: $start_date"
echo "=================================================="
echo ""

start_time=$(date +%s)

if [ "$use_compression" == "tak" ] && [ "$use_split" == "tak" ]; then
    if [ "$use_backup" == "tak" ]; then
        dd if="$source_path" bs="$block_size" conv=noerror,sync status=progress 2>&1 | tee >(split -b "$split_size" - "${dest_path}.part_") | $compress_cmd > "$backup_path"
        dd_exit_code=${PIPESTATUS[0]}
    else
        dd if="$source_path" bs="$block_size" conv=noerror,sync status=progress 2>&1 | $compress_cmd | split -b "$split_size" - "${dest_path}.part_"
        dd_exit_code=${PIPESTATUS[0]}
    fi
elif [ "$use_compression" == "tak" ]; then
    if [ "$use_backup" == "tak" ]; then
        dd if="$source_path" bs="$block_size" conv=noerror,sync status=progress 2>&1 | tee >($compress_cmd > "$backup_path") | $compress_cmd > "$dest_path"
        dd_exit_code=${PIPESTATUS[0]}
    else
        dd if="$source_path" bs="$block_size" conv=noerror,sync status=progress 2>&1 | $compress_cmd > "$dest_path"
        dd_exit_code=${PIPESTATUS[0]}
    fi
elif [ "$use_split" == "tak" ]; then
    if [ "$use_backup" == "tak" ]; then
        dd if="$source_path" bs="$block_size" conv=noerror,sync status=progress 2>&1 | tee >(split -b "$split_size" - "${dest_path}.part_") > "$backup_path"
        dd_exit_code=${PIPESTATUS[0]}
    else
        dd if="$source_path" bs="$block_size" conv=noerror,sync status=progress 2>&1 | split -b "$split_size" - "${dest_path}.part_"
        dd_exit_code=${PIPESTATUS[0]}
    fi
else
    if [ "$use_backup" == "tak" ]; then
        dd if="$source_path" of="$dest_path" bs="$block_size" conv=noerror,sync status=progress 2>&1 | tee "$backup_path"
        dd_exit_code=${PIPESTATUS[0]}
    else
        dd if="$source_path" of="$dest_path" bs="$block_size" conv=noerror,sync status=progress 2>&1
        dd_exit_code=$?
    fi
fi

end_time=$(date +%s)
elapsed=$((end_time - start_time))

echo ""
echo "=================================================="

if [ $dd_exit_code -eq 0 ]; then
    log_message "Operacja DD zakończona pomyślnie"
    echo "Operacja DD zakończona pomyślnie"
    echo "Czas trwania: ${elapsed}s"
    
    if [[ "$do_sync" =~ ^[Tt]$ ]]; then
        log_message "Rozpoczęcie synchronizacji"
        echo "Synchronizacja danych na dysk..."
        sync
        log_message "Synchronizacja zakończona"
        echo "Synchronizacja zakończona"
    fi
    
    if [[ "$do_verify" =~ ^[Tt]$ ]] && [ "$use_compression" != "tak" ] && [ "$use_split" != "tak" ]; then
        verify_integrity "$source_path" "$dest_path"
    fi
    
    if [[ "$do_forensic" =~ ^[Tt]$ ]]; then
        export_forensic_report
    fi
    
    log_to_history "$OPERATION_ID | $(date '+%Y-%m-%d %H:%M:%S') | $source_path -> $dest_path | $elapsed s | SUKCES"
    
    echo ""
    echo "Wszystkie operacje zakończone"
    echo "Czas zakończenia: $(date '+%Y-%m-%d %H:%M:%S')"
    log_message "Wszystkie operacje zakończone pomyślnie"
else
    log_message "BŁĄD podczas operacji DD - kod: $dd_exit_code"
    echo "Błąd podczas operacji DD"
    echo "Kod wyjścia: $dd_exit_code"
    log_to_history "$OPERATION_ID | $(date '+%Y-%m-%d %H:%M:%S') | $source_path -> $dest_path | $elapsed s | BŁĄD"
    exit 1
fi

echo "=================================================="
echo ""
echo "Logi operacji: $OPERATION_LOG"

if [[ "$do_forensic" =~ ^[Tt]$ ]]; then
    echo "Raport forensic: $METADATA_DIR/forensic_report_${OPERATION_ID}.txt"
fi

log_message "Zakończenie operacji"
