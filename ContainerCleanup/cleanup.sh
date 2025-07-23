#!/bin/bash

# Container Cleanup Script - Finds and removes orphaned resources
# Run this to clean up the mess created by the mess creator script

set -e

echo "Starting container cleanup scan..."
echo ""

# Initialize counters
TOTAL_CLEANED=0
TOTAL_SIZE_CLEANED=0

# 1. Find and clean orphaned Docker volumes
echo "1. Scanning for orphaned volumes..."
ORPHANED_VOLUMES=$(docker volume ls -qf dangling=true 2>/dev/null || true)
if [ -n "$ORPHANED_VOLUMES" ]; then
    VOLUME_COUNT=$(echo "$ORPHANED_VOLUMES" | wc -l)
    echo "   Found $VOLUME_COUNT orphaned volumes:"
    echo "$ORPHANED_VOLUMES" | sed 's/^/   - /'
    echo "   Cleaning up..."
    echo "$ORPHANED_VOLUMES" | xargs docker volume rm 2>/dev/null || true
    echo "   CLEANED: Removed $VOLUME_COUNT orphaned volumes"
    TOTAL_CLEANED=$((TOTAL_CLEANED + VOLUME_COUNT))
else
    echo "   No orphaned volumes found"
fi
echo ""

# 2. Find and clean orphaned networks
echo "2. Scanning for orphaned networks..."
CUSTOM_NETWORKS=$(docker network ls --filter type=custom -q 2>/dev/null || true)
ORPHANED_NETWORKS=""
for net in $CUSTOM_NETWORKS; do
    if [ -z "$(docker ps -aq --filter network=$net 2>/dev/null)" ]; then
        NET_NAME=$(docker network ls --filter id=$net --format "{{.Name}}" 2>/dev/null || true)
        if [[ "$NET_NAME" != "bridge" && "$NET_NAME" != "host" && "$NET_NAME" != "none" && -n "$NET_NAME" ]]; then
            ORPHANED_NETWORKS="$ORPHANED_NETWORKS $net"
        fi
    fi
done

if [ -n "$ORPHANED_NETWORKS" ]; then
    NETWORK_COUNT=$(echo "$ORPHANED_NETWORKS" | wc -w)
    echo "   Found $NETWORK_COUNT orphaned networks:"
    for net in $ORPHANED_NETWORKS; do
        NET_NAME=$(docker network ls --filter id=$net --format "{{.Name}}" 2>/dev/null || echo "unknown")
        echo "   - $NET_NAME ($net)"
    done
    echo "   Cleaning up..."
    echo "$ORPHANED_NETWORKS" | xargs docker network rm 2>/dev/null || true
    echo "   CLEANED: Removed $NETWORK_COUNT orphaned networks"
    TOTAL_CLEANED=$((TOTAL_CLEANED + NETWORK_COUNT))
else
    echo "   No orphaned networks found"
fi
echo ""

# 3. Find large temp files in bind mounts
echo "3. Scanning for container temp files..."
TEMP_DIRS=$(find /tmp -maxdepth 1 -name "*container*" -type d 2>/dev/null || true)
LARGE_FILES=$(find /tmp -maxdepth 2 -name "*container*" -type f -size +1M 2>/dev/null || true)

if [ -n "$TEMP_DIRS" ] || [ -n "$LARGE_FILES" ]; then
    if [ -n "$TEMP_DIRS" ]; then
        echo "   Found container temp directories:"
        echo "$TEMP_DIRS" | sed 's/^/   - /'
    fi
    if [ -n "$LARGE_FILES" ]; then
        echo "   Found large temp files:"
        echo "$LARGE_FILES" | sed 's/^/   - /'
    fi
    
    # Calculate total size before cleanup
    TEMP_SIZE_KB=0
    if ls /tmp/*container* >/dev/null 2>&1; then
        TEMP_SIZE_KB=$(du -sk /tmp/*container* 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    fi
    TEMP_SIZE_MB=$((TEMP_SIZE_KB / 1024))
    echo "   Total size: ${TEMP_SIZE_MB}MB"
    
    read -p "   Remove these files? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Count directories and files safely
        TEMP_COUNT=0
        FILE_COUNT=0
        if [ -n "$TEMP_DIRS" ]; then
            TEMP_COUNT=$(echo "$TEMP_DIRS" | wc -l)
        fi
        if [ -n "$LARGE_FILES" ]; then
            FILE_COUNT=$(echo "$LARGE_FILES" | wc -l)
        fi
        
        rm -rf /tmp/*container* 2>/dev/null || true
        echo "   CLEANED: Removed $TEMP_COUNT directories and $FILE_COUNT large files (${TEMP_SIZE_MB}MB)"
        TOTAL_CLEANED=$((TOTAL_CLEANED + TEMP_COUNT + FILE_COUNT))
        TOTAL_SIZE_CLEANED=$((TOTAL_SIZE_CLEANED + TEMP_SIZE_MB))
    else
        echo "   SKIPPED: Temp file cleanup"
    fi
else
    echo "   No container temp files found"
fi
echo ""

# 4. Find named pipes and sockets
echo "4. Scanning for named pipes and sockets..."
PIPES=$(find /tmp -name "*container*pipe*" -type p 2>/dev/null || true)
SOCKETS=$(find /tmp -name "*container*socket*" -o -name "*.sock" 2>/dev/null | grep container 2>/dev/null || true)

if [ -n "$PIPES" ] || [ -n "$SOCKETS" ]; then
    PIPE_COUNT=0
    SOCKET_COUNT=0
    if [ -n "$PIPES" ]; then
        PIPE_COUNT=$(echo "$PIPES" | wc -l)
        echo "   Found $PIPE_COUNT named pipes:"
        echo "$PIPES" | sed 's/^/   - /'
    fi
    if [ -n "$SOCKETS" ]; then
        SOCKET_COUNT=$(echo "$SOCKETS" | wc -l)
        echo "   Found $SOCKET_COUNT socket files:"
        echo "$SOCKETS" | sed 's/^/   - /'
    fi
    
    rm -f $PIPES $SOCKETS 2>/dev/null || true
    echo "   CLEANED: Removed $PIPE_COUNT pipes and $SOCKET_COUNT sockets"
    TOTAL_CLEANED=$((TOTAL_CLEANED + PIPE_COUNT + SOCKET_COUNT))
else
    echo "   No orphaned pipes or sockets found"
fi
echo ""

# 5. Find lock and PID files
echo "5. Scanning for lock and PID files..."
LOCK_DIRS=$(find /tmp -name "*container-locks*" -type d 2>/dev/null || true)
LOCK_FILES=$(find /tmp -name "*.pid" -o -name "*.lock" 2>/dev/null | grep -E "(container|app|worker)" 2>/dev/null || true)

if [ -n "$LOCK_DIRS" ] || [ -n "$LOCK_FILES" ]; then
    LOCK_DIR_COUNT=0
    LOCK_FILE_COUNT=0
    if [ -n "$LOCK_DIRS" ]; then
        LOCK_DIR_COUNT=$(echo "$LOCK_DIRS" | wc -l)
        echo "   Found $LOCK_DIR_COUNT lock directories:"
        echo "$LOCK_DIRS" | sed 's/^/   - /'
    fi
    if [ -n "$LOCK_FILES" ]; then
        LOCK_FILE_COUNT=$(echo "$LOCK_FILES" | wc -l)
        echo "   Found $LOCK_FILE_COUNT lock/PID files:"
        echo "$LOCK_FILES" | sed 's/^/   - /'
    fi
    
    rm -rf $LOCK_DIRS 2>/dev/null || true
    rm -f $LOCK_FILES 2>/dev/null || true
    echo "   CLEANED: Removed $LOCK_DIR_COUNT directories and $LOCK_FILE_COUNT lock/PID files"
    TOTAL_CLEANED=$((TOTAL_CLEANED + LOCK_DIR_COUNT + LOCK_FILE_COUNT))
else
    echo "   No lock or PID files found"
fi
echo ""

# 6. Find database data directories
echo "6. Scanning for database data directories..."
DB_DIRS=$(find /tmp -name "*pg-data*" -type d 2>/dev/null || true)
if [ -n "$DB_DIRS" ]; then
    DB_COUNT=$(echo "$DB_DIRS" | wc -l)
    echo "   Found $DB_COUNT database directories:"
    echo "$DB_DIRS" | sed 's/^/   - /'
    DB_SIZE_KB=$(du -sk $DB_DIRS 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    DB_SIZE_MB=$((DB_SIZE_KB / 1024))
    echo "   Total size: ${DB_SIZE_MB}MB"
    
    read -p "   Remove database data? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf $DB_DIRS 2>/dev/null || true
        echo "   CLEANED: Removed $DB_COUNT database directories (${DB_SIZE_MB}MB)"
        TOTAL_CLEANED=$((TOTAL_CLEANED + DB_COUNT))
        TOTAL_SIZE_CLEANED=$((TOTAL_SIZE_CLEANED + DB_SIZE_MB))
    else
        echo "   SKIPPED: Database cleanup"
    fi
else
    echo "   No database directories found"
fi
echo ""

# 7. Find large log files
echo "7. Scanning for container log files..."
LOG_DIRS=$(find /tmp -name "*container-logs*" -type d 2>/dev/null || true)
LARGE_LOGS=$(find /tmp -name "*.log" -size +5M 2>/dev/null | head -10 || true)

if [ -n "$LOG_DIRS" ] || [ -n "$LARGE_LOGS" ]; then
    LOG_DIR_COUNT=0
    LOG_FILE_COUNT=0
    if [ -n "$LOG_DIRS" ]; then
        LOG_DIR_COUNT=$(echo "$LOG_DIRS" | wc -l)
        echo "   Found $LOG_DIR_COUNT log directories:"
        echo "$LOG_DIRS" | sed 's/^/   - /'
    fi
    if [ -n "$LARGE_LOGS" ]; then
        LOG_FILE_COUNT=$(echo "$LARGE_LOGS" | wc -l)
        echo "   Found $LOG_FILE_COUNT large log files:"
        echo "$LARGE_LOGS" | head -5 | sed 's/^/   - /'
    fi
    
    if [ -n "$LOG_DIRS" ]; then
        LOG_SIZE_KB=$(du -sk $LOG_DIRS 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
        LOG_SIZE_MB=$((LOG_SIZE_KB / 1024))
        echo "   Total log size: ${LOG_SIZE_MB}MB"
        rm -rf $LOG_DIRS 2>/dev/null || true
        echo "   CLEANED: Removed $LOG_DIR_COUNT log directories (${LOG_SIZE_MB}MB)"
        TOTAL_CLEANED=$((TOTAL_CLEANED + LOG_DIR_COUNT))
        TOTAL_SIZE_CLEANED=$((TOTAL_SIZE_CLEANED + LOG_SIZE_MB))
    fi
else
    echo "   No large container log files found"
fi
echo ""

# 8. Check shared memory usage
echo "8. Checking shared memory usage..."
SHM_USAGE=$(df -h /dev/shm 2>/dev/null | tail -1 | awk '{print $3 " / " $2 " (" $5 ")"}' || echo "unavailable")
echo "   Shared memory usage: $SHM_USAGE"
SHM_FILES=$(find /dev/shm -name "*app*" -o -name "*container*" 2>/dev/null || true)
if [ -n "$SHM_FILES" ]; then
    SHM_COUNT=$(echo "$SHM_FILES" | wc -l)
    echo "   Found $SHM_COUNT container shared memory files:"
    echo "$SHM_FILES" | sed 's/^/   - /'
    SHM_SIZE_KB=$(du -sk $SHM_FILES 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    SHM_SIZE_MB=$((SHM_SIZE_KB / 1024))
    rm -rf $SHM_FILES 2>/dev/null || true
    echo "   CLEANED: Removed $SHM_COUNT shared memory files (${SHM_SIZE_MB}MB)"
    TOTAL_CLEANED=$((TOTAL_CLEANED + SHM_COUNT))
    TOTAL_SIZE_CLEANED=$((TOTAL_SIZE_CLEANED + SHM_SIZE_MB))
else
    echo "   No container shared memory files found"
fi
echo ""

# 9. Find background process work files
echo "9. Scanning for background process files..."
BG_DIRS=$(find /tmp -name "*bg-work*" -type d 2>/dev/null || true)
if [ -n "$BG_DIRS" ]; then
    BG_COUNT=$(echo "$BG_DIRS" | wc -l)
    echo "   Found $BG_COUNT background work directories:"
    echo "$BG_DIRS" | sed 's/^/   - /'
    
    # Check if any processes are still writing to these
    PROCESSES_FOUND=0
    for dir in $BG_DIRS; do
        if lsof "$dir"/* 2>/dev/null | grep -q .; then
            PROCESSES_FOUND=1
            echo "   WARNING: Some files still in use by processes"
            break
        fi
    done
    
    BG_SIZE_KB=$(du -sk $BG_DIRS 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    BG_SIZE_MB=$((BG_SIZE_KB / 1024))
    rm -rf $BG_DIRS 2>/dev/null || true
    echo "   CLEANED: Removed $BG_COUNT background work directories (${BG_SIZE_MB}MB)"
    TOTAL_CLEANED=$((TOTAL_CLEANED + BG_COUNT))
    TOTAL_SIZE_CLEANED=$((TOTAL_SIZE_CLEANED + BG_SIZE_MB))
else
    echo "   No background work files found"
fi
echo ""

# 10. Clean dangling images
echo "10. Scanning for dangling Docker images..."
DANGLING_IMAGES=$(docker images -f "dangling=true" -q 2>/dev/null || true)
if [ -n "$DANGLING_IMAGES" ]; then
    DANGLING_COUNT=$(echo "$DANGLING_IMAGES" | wc -l)
    echo "   Found $DANGLING_COUNT dangling images"
    
    # Clean up and capture output
    CLEANUP_OUTPUT=$(docker image prune -f 2>&1 || true)
    RECLAIMED_SPACE=$(echo "$CLEANUP_OUTPUT" | grep -o '[0-9.]*[KMGT]B' | tail -1 || echo "unknown")
    
    echo "   CLEANED: Removed $DANGLING_COUNT dangling images"
    if [ "$RECLAIMED_SPACE" != "unknown" ]; then
        echo "   RECLAIMED: $RECLAIMED_SPACE of disk space"
    fi
    TOTAL_CLEANED=$((TOTAL_CLEANED + DANGLING_COUNT))
else
    echo "   No dangling images found"
fi

echo ""
echo "=========================================="
echo "CLEANUP SUMMARY"
echo "=========================================="
echo "Total items cleaned: $TOTAL_CLEANED"
echo "Total disk space reclaimed: ${TOTAL_SIZE_CLEANED}MB"
echo ""
echo "Final system status:"
echo ""
echo "Docker system usage:"
docker system df 2>/dev/null || echo "Docker system df unavailable"
echo ""
echo "Disk usage in /tmp:"
df -h /tmp 2>/dev/null || echo "/tmp disk usage unavailable"
echo ""
echo "Shared memory usage:"
df -h /dev/shm 2>/dev/null || echo "Shared memory usage unavailable"
echo ""
echo "Cleanup completed successfully!"
