from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time


class MyHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"File created: {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory:
            print(f"File modified: {event.src_path}")


# Folder to monitor
folder_to_watch = "."

# Create event handler and observer
event_handler = MyHandler()
observer = Observer()

observer.schedule(
    event_handler,
    path=folder_to_watch,
    recursive=True,
)

# Start watching
observer.start()

print(f"Watching: {folder_to_watch}")
print("Press Ctrl+C to stop.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nStopping file watcher...")
finally:
    observer.stop()
    observer.join()
    print("File watcher stopped.")