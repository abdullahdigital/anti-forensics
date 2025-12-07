import struct
import os
import sys
import win32file
import win32api
import win32con
from datetime import datetime

# Constants for USN Journal operations
FSCTL_QUERY_USN_JOURNAL = 0x900f4
FSCTL_READ_USN_JOURNAL = 0x900eb
FSCTL_CREATE_USN_JOURNAL = 0x900f0
FSCTL_DELETE_USN_JOURNAL = 0x900f4

# USN Reasons (from winnt.h)
USN_REASON_DATA_OVERWRITE = 0x00000001
USN_REASON_EXTEND_DATA = 0x00000002
USN_REASON_APPEND_DATA = 0x00000004
USN_REASON_TRUNCATE_DATA = 0x00000008
USN_REASON_COMPRESSION_CHANGE = 0x00000010
USN_REASON_ENCRYPTION_CHANGE = 0x00000020
USN_REASON_OBJECT_ID_CHANGE = 0x00000040
USN_REASON_REPARSE_POINT_CHANGE = 0x00000080
USN_REASON_STREAM_CHANGE = 0x00000100
USN_REASON_INDEXABLE_CHANGE = 0x00000200
USN_REASON_SECURITY_CHANGE = 0x00000400
USN_REASON_HARD_LINK_CHANGE = 0x00000800
USN_REASON_COMPACT_HASH_CHANGE = 0x00001000
USN_REASON_NAMED_DATA_OVERWRITE = 0x00002000
USN_REASON_NAMED_DATA_EXTEND = 0x00004000
USN_REASON_NAMED_DATA_APPEND = 0x00008000
USN_REASON_NAMED_DATA_TRUNCATE = 0x00010000
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_FILE_DELETE = 0x00000200
USN_REASON_EA_CHANGE = 0x00000400
USN_REASON_SECURITY_CHANGE = 0x00000800
USN_REASON_RENAME_OLD_NAME = 0x00001000
USN_REASON_RENAME_NEW_NAME = 0x00002000
USN_REASON_CLOSE = 0x80000000

# USN_RECORD_V2 structure fields and their offsets/sizes
# This is based on the documentation for USN_RECORD_V2
# (https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-usn_record_v2)
USN_RECORD_V2_FORMAT = (
    '<L'   # RecordLength
    'L'   # MajorVersion
    'L'   # MinorVersion
    'Q'   # FileReferenceNumber
    'Q'   # ParentFileReferenceNumber
    'Q'   # Usn
    'Q'   # TimeStamp (FILETIME)
    'L'   # Reason
    'L'   # SourceInfo
    'L'   # SecurityId
    'L'   # FileAttributes
    'L'   # FileNameLength
    'L'   # FileNameOffset
) # Total 60 bytes for fixed part
USN_RECORD_V2_FIXED_SIZE = struct.calcsize(USN_RECORD_V2_FORMAT)

def open_volume_handle(drive_letter):
    """
    Opens a handle to the specified volume.
    """
    volume_path = "\\\\.\\" + drive_letter + ":"
    try:
        handle = win32file.CreateFile(
            volume_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )
        return handle
    except win32api.error as e:
        print(f"Error opening volume {volume_path}: {e}")
        return None

def query_usn_journal(handle):
    """
    Queries the USN Journal for its properties.
    """
    try:
        usn_journal_data = win32file.DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            None,
            64,  # Size of USN_JOURNAL_DATA_V0 structure
            None
        )
        # Parse the returned bytes into USN_JOURNAL_DATA_V0 structure
        # (UsnJournalID, FirstUsn, NextUsn, LowestValidUsn, MaxUsn, MaximumSize, AllocationDelta)
        usn_journal_id, first_usn, next_usn, lowest_valid_usn, max_usn, maximum_size, allocation_delta = \
            struct.unpack('<QQQQQQQ', usn_journal_data[:56]) # V0 is 56 bytes, V1 is 64 bytes
        
        return {
            "UsnJournalID": usn_journal_id,
            "FirstUsn": first_usn,
            "NextUsn": next_usn,
            "LowestValidUsn": lowest_valid_usn,
            "MaxUsn": max_usn,
            "MaximumSize": maximum_size,
            "AllocationDelta": allocation_delta
        }
    except win32api.error as e:
        print(f"Error querying USN Journal: {e}")
        return None

def parse_usn_record(record_bytes):
    """
    Parses a single USN_RECORD_V2 byte string into a dictionary.
    """
    if len(record_bytes) < USN_RECORD_V2_FIXED_SIZE:
        return None

    (RecordLength, MajorVersion, MinorVersion, FileReferenceNumber,
     ParentFileReferenceNumber, Usn, TimeStamp, Reason, SourceInfo,
     SecurityId, FileAttributes, FileNameLength, FileNameOffset) = \
        struct.unpack(USN_RECORD_V2_FORMAT, record_bytes[:USN_RECORD_V2_FIXED_SIZE])

    # Convert FILETIME to datetime
    # FILETIME is 100-nanosecond intervals since January 1, 1601 (UTC)
    # Python datetime uses seconds since January 1, 1970 (UTC)
    # 116444736000000000 is the number of 100-nanosecond intervals between 1601-01-01 and 1970-01-01
    timestamp_seconds = (TimeStamp - 116444736000000000) / 10000000
    try:
        dt_object = datetime.utcfromtimestamp(timestamp_seconds)
    except ValueError:
        dt_object = None # Handle cases where timestamp might be invalid

    # Extract filename
    # FileNameOffset is relative to the start of the USN_RECORD structure
    # FileNameLength is in bytes
    filename_start = FileNameOffset
    filename_end = FileNameOffset + FileNameLength
    filename = record_bytes[filename_start:filename_end].decode('utf-16-le', errors='ignore')

    return {
        "RecordLength": RecordLength,
        "MajorVersion": MajorVersion,
        "MinorVersion": MinorVersion,
        "FileReferenceNumber": FileReferenceNumber,
        "ParentFileReferenceNumber": ParentFileReferenceNumber,
        "Usn": Usn,
        "TimeStamp": dt_object.isoformat() if dt_object else None,
        "Reason": Reason,
        "SourceInfo": SourceInfo,
        "SecurityId": SecurityId,
        "FileAttributes": FileAttributes,
        "FileNameLength": FileNameLength,
        "FileNameOffset": FileNameOffset,
        "FileName": filename
    }

def read_usn_journal_records(handle, start_usn, reason_mask, usn_journal_id):
    """
    Reads USN Journal records from the specified volume and parses them.
    """
    read_data = struct.pack(
        '<QQQQQQ',
        start_usn,          # StartUsn
        reason_mask,        # ReasonMask
        0,                  # ReturnOnlyOnClose (0 = false)
        0,                  # Timeout (0 = no timeout)
        0,                  # BytesToWaitFor (0 = return immediately)
        usn_journal_id      # UsnJournalID
    )
    
    output_buffer_size = 1024 * 1024  # 1 MB buffer
    output_buffer = win32file.AllocateReadBuffer(output_buffer_size)

    records = []
    try:
        bytes_returned = win32file.DeviceIoControl(
            handle,
            FSCTL_READ_USN_JOURNAL,
            read_data,
            output_buffer,
            None
        )
        
        current_offset = 0
        # The first 8 bytes of the output buffer contain the NextUsn to use for the next read
        next_usn_for_next_read = struct.unpack('<Q', output_buffer[0:8])[0]
        current_offset += 8 # Skip the NextUsn field

        while current_offset < bytes_returned:
            # Read RecordLength from the current record to determine its size
            if current_offset + 4 > bytes_returned: # Ensure we can read RecordLength
                break
            record_length = struct.unpack('<L', output_buffer[current_offset:current_offset+4])[0]
            
            if record_length == 0: # Should not happen, but as a safeguard
                break

            record_bytes = output_buffer[current_offset : current_offset + record_length]
            parsed_record = parse_usn_record(record_bytes)
            if parsed_record:
                records.append(parsed_record)
            
            current_offset += record_length

        return records, next_usn_for_next_read
    except win32api.error as e:
        print(f"Error reading USN Journal: {e}")
        return [], start_usn

def get_path_from_frn(volume_handle, frn):
    """
    Attempts to get the full path of a file/directory given its File Reference Number (FRN).
    This is a complex operation and might not always succeed, especially for deleted files.
    """
    try:
        # Open the file by its File ID (FRN)
        file_handle = win32file.OpenFileById(
            volume_handle,
            frn,
            0, # dwDesiredAccess (0 for query access)
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )

        # Get the final path name from the handle
        # FILE_NAME_NORMALIZED returns the path with short names expanded to long names
        path = win32file.GetFinalPathNameByHandle(file_handle, win32con.FILE_NAME_NORMALIZED)
        win32file.CloseHandle(file_handle)
        return path
    except win32api.error as e:
        # print(f"Error getting path for FRN {frn}: {e}")
        return None

def process_usn_records_for_renames(usn_records):
    """
    Processes a list of parsed USN records to identify and pair rename events.
    Returns a list of dictionaries, each representing a rename event.
    Each dictionary will contain 'old_filename', 'new_filename', 'file_reference_number', 'parent_file_reference_number', and 'timestamp'.
    Note: This function only extracts filenames and FRNs. Full path reconstruction is not performed here.
    """
    rename_events = []
    old_name_records = {}

    for record in usn_records:
        frn = record["FileReferenceNumber"]
        reason = record["Reason"]

        if reason & USN_REASON_RENAME_OLD_NAME:
            # Store the old name record, keyed by FRN
            old_name_records[frn] = {
                "filename": record["FileName"],
                "parent_frn": record["ParentFileReferenceNumber"],
                "timestamp": record["TimeStamp"]
            }
        elif reason & USN_REASON_RENAME_NEW_NAME:
            # If a new name record is found, try to match it with an old name record
            if frn in old_name_records:
                old_record_info = old_name_records.pop(frn) # Remove it once matched
                rename_events.append({
                    "old_filename": old_record_info["filename"],
                    "new_filename": record["FileName"],
                    "file_reference_number": frn,
                    "old_parent_file_reference_number": old_record_info["parent_frn"],
                    "new_parent_file_reference_number": record["ParentFileReferenceNumber"],
                    "timestamp": record["TimeStamp"]
                })
            else:
                # This might happen if the old_name_record was outside the current batch of records
                # Or if the journal was reset, etc.
                # For now, we'll just log it or handle as an unmatched new name
                print(f"Warning: Unmatched RENAME_NEW_NAME record for FRN {frn}: {record["FileName"]}")

    return rename_events

def get_file_frn(file_path):
    """
    Retrieves the File Reference Number (FRN) for a given file.
    """
    try:
        # Open the file with FILE_FLAG_BACKUP_SEMANTICS for directories
        # and to get file handles for files.
        flags = win32con.FILE_FLAG_BACKUP_SEMANTICS
        if not os.path.isdir(file_path):
            flags |= win32con.FILE_ATTRIBUTE_NORMAL

        handle = win32file.CreateFile(
            file_path,
            0, # dwDesiredAccess (0 for query access)
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
            None,
            win32file.OPEN_EXISTING,
            flags,
            None
        )

        # Get the file information by handle
        # FILE_ID_INFO is available from Windows Vista onwards
        file_info = win32file.GetFileInformationByHandleEx(handle, win32file.FileIdInfo)
        win32file.CloseHandle(handle)

        # FileId is a 16-byte structure, the FRN is the first 8 bytes (low part of the FileId)
        # For NTFS, the FileId is a 64-bit value, so we take the first 8 bytes.
        frn = struct.unpack('<Q', file_info.FileId[:8])[0]
        return frn
    except win32api.error as e:
        # print(f"Error getting FRN for {file_path}: {e}")
        return None

if __name__ == "__main__":
    # Example usage
    drive = "C" # Or any other drive letter
    handle = open_volume_handle(drive)
    if handle:
        journal_info = query_usn_journal(handle)
        if journal_info:
            print("USN Journal Info:")
            for key, value in journal_info.items():
                print(f"  {key}: {value}")
            
            # Read records from the beginning of the journal for demonstration
            # In a real scenario, you'd want to store the last read USN and continue from there
            reason_mask = (
                USN_REASON_FILE_CREATE | USN_REASON_FILE_DELETE | 
                USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME | 
                USN_REASON_CLOSE | USN_REASON_DATA_OVERWRITE
            ) # Example reasons to filter
            
            # Start reading from the LowestValidUsn to get historical data
            # For continuous monitoring, you'd start from the last NextUsn returned
            records, next_usn = read_usn_journal_records(handle, journal_info["LowestValidUsn"], reason_mask, journal_info["UsnJournalID"])
            
            print(f"\nRead {len(records)} USN records.")
            for i, record in enumerate(records):
                print(f"\n--- Record {i+1} ---")
                for key, value in record.items():
                    print(f"  {key}: {value}")
                
                if record["Reason"] & USN_REASON_RENAME_OLD_NAME:
                    print("  !!! RENAME_OLD_NAME detected !!!")
                if record["Reason"] & USN_REASON_RENAME_NEW_NAME:
                    print("  !!! RENAME_NEW_NAME detected !!!")

            rename_events = process_usn_records_for_renames(records)
            if rename_events:
                print("\n--- Detected Rename Events ---")
                for event in rename_events:
                    print(f"  Old Name: {event['old_filename']}")
                    print(f"  New Name: {event['new_filename']}")
                    print(f"  File FRN: {event['file_reference_number']}")
                    print(f"  Old Parent FRN: {event['old_parent_file_reference_number']}")
                    print(f"  New Parent FRN: {event['new_parent_file_reference_number']}")
                    print(f"  Timestamp: {event['timestamp']}")
            else:
                print("\nNo rename events detected in the processed records.")

        win32file.CloseHandle(handle)
    else:
        print(f"Could not open handle for drive {drive}.")
