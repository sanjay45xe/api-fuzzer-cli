import os
import shutil

def main():
    # Identify path locations
    root_dir = os.path.dirname(os.path.abspath(__file__))
    outer_fuzzer = os.path.join(root_dir, "fuzzer")
    inner_fuzzer = os.path.join(outer_fuzzer, "fuzzer")
    
    if not os.path.exists(inner_fuzzer):
        print(f"Error: Nested inner folder '{inner_fuzzer}' not found.")
        print("Please check if the files have already been moved or run the script in the 'API Fuzzing' root folder.")
        return
        
    print(f"Restructuring fuzzer package. Moving files from:\n  -> {inner_fuzzer}\nto:\n  -> {outer_fuzzer}\n")
    
    # Dynamic list of files in the inner folder to move
    try:
        inner_items = os.listdir(inner_fuzzer)
    except Exception as e:
        print(f"Error reading inner fuzzer directory: {e}")
        return

    for item in inner_items:
        src = os.path.join(inner_fuzzer, item)
        dst = os.path.join(outer_fuzzer, item)
        
        # Don't move if it's the __pycache__ directory itself, we can delete it
        if item == "__pycache__" and os.path.isdir(src):
            shutil.rmtree(src)
            print("Removed __pycache__ from inner folder.")
            continue
            
        print(f"Moving: {item}")
        shutil.move(src, dst)
            
    # Remove the inner fuzzer folder now that it's empty
    try:
        os.rmdir(inner_fuzzer)
        print("\nSuccessfully deleted empty inner fuzzer directory.")
    except Exception as e:
        print(f"\nWarning: Could not delete inner directory: {e}")
        
    # Verify and print results
    print("\n--- Verification ---")
    print(f"Files directly in '{outer_fuzzer}':")
    for file in os.listdir(outer_fuzzer):
        print(f"  - {file}")

if __name__ == "__main__":
    main()
