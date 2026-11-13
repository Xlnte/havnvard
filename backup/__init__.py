"""HavnVard Backup (2.0.0): restic backups as a HavnVard feature.

Standard library only. Never runs sudo or systemctl to install anything: units are
rendered to an output directory and the install commands are printed. Secrets live
under ~/.config/havnvard/ and are never printed or committed.
"""
__version__ = "3.2.0"
