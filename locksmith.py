#!/usr/bin/env python3
import sys
import subprocess
import os

def get_locking_processes(file_path):
    try:
        # lsof returns 0 if it finds processes, 1 if not, >1 on error
        # Use +D for directory path to be searched recursively
        cmd = ['lsof', '-t']
        if os.path.isdir(file_path):
            cmd.append('+D')
        cmd.append(file_path)

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            pids = result.stdout.strip().split('\n')
            return pids
        elif result.returncode == 1:
            return []
        else:
            # Check for permission errors in stderr
            if "permission denied" in result.stderr.lower():
                return "PERMISSION_DENIED"
            return []
    except Exception as e:
        print(f"Error querying lsof: {e}")
        return []

def get_process_info(pid):
    try:
        # Get user and command for PID
        result = subprocess.run(['ps', '-o', 'user=,comm=', '-p', pid], capture_output=True, text=True)
        if result.returncode == 0:
            parts = result.stdout.strip().split(maxsplit=1)
            if len(parts) >= 2:
                return parts[0], parts[1]
        return "unknown", "unknown"
    except:
        return "unknown", "unknown"

def main():
    if len(sys.argv) != 2:
        print("Usage: ./locksmith <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]

    # Check if path exists
    if not os.path.exists(file_path):
        print(f"Error: Path '{file_path}' does not exist.")
        sys.exit(1)

    print(f"Checking for locks on: {file_path}...\n")
    pids = get_locking_processes(file_path)

    if pids == "PERMISSION_DENIED":
        print("Access denied. No process locks found, but path is inaccessible due to permissions.")
        choice = input("Do you want to safely update permissions (chmod +r)? (y/n): ").strip().lower()
        if choice == 'y':
            try:
                subprocess.run(['chmod', '+r', file_path], check=True)
                print("Permissions updated. Please run locksmith again.")
            except subprocess.CalledProcessError:
                print("Failed to update permissions. You might need sudo.")
        return

    if not pids:
        print("No processes holding locks detected.")
        return

    # Extract unique PIDs and filter empty strings
    unique_pids = sorted(list(set([p.strip() for p in pids if p.strip()])))

    print(f"{'PID':<10} {'USER':<15} {'PROCESS NAME'}")
    print("-" * 45)

    process_details = []
    for pid in unique_pids:
        user, comm = get_process_info(pid)
        process_details.append({'pid': pid, 'user': user, 'comm': comm})
        print(f"{pid:<10} {user:<15} {comm}")

    while True:
        print("\nOptions:")
        print("  <pid1,pid2,...> : Terminate specific PIDs (comma-separated)")
        print("  all             : Unlock all (terminate all listed PIDs)")
        print("  q               : Quit")

        choice = input("\nChoice: ").strip().lower()

        if choice == 'q':
            break

        pids_to_kill = []
        if choice == 'all':
            pids_to_kill = [p['pid'] for p in process_details]
        else:
            pids_to_kill = [p.strip() for p in choice.split(',')]

        for pid in pids_to_kill:
            if pid in [p['pid'] for p in process_details]:
                print(f"Terminating process {pid}...")
                try:
                    subprocess.run(['kill', '-9', pid], check=True)
                    print(f"Successfully terminated {pid}.")
                except subprocess.CalledProcessError:
                    print(f"Failed to terminate {pid}. (Requires root?)")
            else:
                if pid:
                    print(f"PID {pid} not in the list of locking processes.")

        # Re-check after killing
        print("\nRe-checking locks...")
        pids = get_locking_processes(file_path)
        if not pids or pids == "PERMISSION_DENIED":
            print("All locks cleared or no longer accessible.")
            break

        unique_pids = sorted(list(set([p.strip() for p in pids if p.strip()])))
        process_details = []
        print(f"\n{'PID':<10} {'USER':<15} {'PROCESS NAME'}")
        print("-" * 45)
        for pid in unique_pids:
            user, comm = get_process_info(pid)
            process_details.append({'pid': pid, 'user': user, 'comm': comm})
            print(f"{pid:<10} {user:<15} {comm}")

if __name__ == "__main__":
    main()
