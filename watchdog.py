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


folder_to_watch = "."

event_handler = MyHandler()
observer = Observer()

observer.schedule(
    event_handler,
    path=folder_to_watch,
    recursive=True
)

observer.start()

print(f"Watching: {folder_to_watch}")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()

observer.join()