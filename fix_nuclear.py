with open('adobo/nuclear.py', 'r') as f:
    content = f.read()

old = '''        interrupted = False
        try:
            self._progress_loop()
        except KeyboardInterrupt:
            interrupted = True
            print(\"\\nInterrupted, stopping all profiles...\")

        self._reap()
        if interrupted:'''

new = '''        interrupted = False
        try:
            self._progress_loop()
        except KeyboardInterrupt:
            interrupted = True
            print(\"\\nInterrupted, stopping all profiles...\")

        self._reap()

        # Clean up multiprocessing queue to avoid atexit traceback on interrupt.
        # The Queue has a background feeder thread that must be joined.
        try:
            if hasattr(self.result_queue, '_writer'):
                writer = self.result_queue._writer
                if writer and writer.is_alive():
                    writer.join(timeout=1.0)
            self.result_queue.close()
            self.result_queue.join_thread()
        except Exception:
            pass

        if interrupted:'''

if old in content:
    content = content.replace(old, new)
    with open('adobo/nuclear.py', 'w') as f:
        f.write(content)
    print('Fixed!')
else:
    print('Pattern not found')
    idx = content.find('interrupted = False')
    if idx >= 0:
        print(f'Found at {idx}')
        print(content[idx:idx+300])
    else:
        print('Not found at all')
