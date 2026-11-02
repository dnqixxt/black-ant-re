import os
import importlib.util

class PluginManager:
    """ Dynamic Plugin Architecture (Phase 9) """
    def __init__(self, plugin_dir="plugins"):
        self.plugin_dir = plugin_dir
        self.plugins = []
        if not os.path.exists(plugin_dir): os.makedirs(plugin_dir)
        self._load_plugins()
        
    def _load_plugins(self):
        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and filename != "__init__.py":
                filepath = os.path.join(self.plugin_dir, filename)
                spec = importlib.util.spec_from_file_location(filename[:-3], filepath)
                mod = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(mod)
                    if hasattr(mod, 'analyze'):
                        self.plugins.append(mod)
                except Exception as e:
                    print(f"Error loading plugin {filename}: {e}")
                
    def run_all(self, data, results):
        for p in self.plugins:
            try: p.analyze(data, results)
            except: pass
