#!/usr/bin/python

import os, sqlite3, sys, shutil

class sqlMerge(object):
    """Basic python script to merge data of 2 !!!IDENTICAL!!!! SQL tables"""

    def __init__(self, parent=None):
        super(sqlMerge, self).__init__()

    def loadTables(self, file_a):
        db_a = sqlite3.connect(file_a)

        cursor_a = db_a.cursor()
        cursor_a.execute("SELECT name FROM sqlite_master WHERE type='table';")

        return cursor_a.fetchall()

    def merge(self, file_a, file_b):
        db_a = sqlite3.connect(file_a)

        print("Merging: " + file_b)
        db_a.execute("ATTACH '" + file_b + "' AS 'db_b'")

        try:
            db_a.execute("BEGIN")
            db_a.execute("INSERT INTO main.certificates(created_at, updated_at, deleted_at, protocol, port, ip, raw) SELECT created_at, updated_at, deleted_at, protocol, port, ip, raw FROM db_b.certificates")
            db_a.commit()
        except sqlite3.Error as e:
            print(e)
            db_a.rollback()

        try:
            db_a.execute("BEGIN")
            db_a.execute("INSERT INTO main.e_dns0(created_at, updated_at, deleted_at, ip, support, timeout) SELECT created_at, updated_at, deleted_at, ip, support, timeout FROM db_b.e_dns0")
            db_a.commit()
        except sqlite3.Error as e:
            print(e)
            db_a.rollback()
       
        try:
            db_a.execute("BEGIN")
            db_a.execute("INSERT INTO main.fast_open_supports(created_at, updated_at, deleted_at, ip, support, port) SELECT created_at, updated_at, deleted_at, ip, support, port FROM db_b.fast_open_supports")
            db_a.commit()
        except sqlite3.Error as e:
            print(e)
            db_a.rollback()

        try:
            db_a.execute("BEGIN")
            db_a.execute("INSERT INTO main.q0_rtt_supports(created_at, updated_at, deleted_at, ip, support, port) SELECT created_at, updated_at, deleted_at, ip, support, port FROM db_b.q0_rtt_supports")
            db_a.commit()
        except sqlite3.Error as e:
            print(e)
            db_a.rollback()
        
        try:
            db_a.execute("BEGIN")
            db_a.execute("INSERT INTO main.q_versions(created_at, updated_at, deleted_at, ip, port, q_version, draft_version) SELECT created_at, updated_at, deleted_at, ip, port, q_version, draft_version FROM db_b.q_versions")
            db_a.commit()
        except sqlite3.Error as e:
            print(e)
            db_a.rollback()

        db_a.execute("detach database db_b")
        db_a.close()

    def read_files(self, directory):
        fname = []
        for root,d_names,f_names in os.walk(directory):
            for f in f_names:
                c_name = os.path.join(root, f)
                filename, file_extension = os.path.splitext(c_name)
                if (file_extension == '.db'):
                    fname.append(c_name)
        return fname

    def batch_merge(self, directory):
        db_files = self.read_files(directory)
        result_file = os.path.join(directory, "merged.db")
        shutil.copyfile(db_files[0], result_file)
        print("db_basis: ", db_files[0])
        print("merged_file_name: ", result_file)
        for db_file in db_files[1:]:
            self.merge(result_file, db_file)
            # print(db_file)
            continue

    def main(self):
        folder = sys.argv[1] if len(sys.argv) > 0 else "."
        self.batch_merge(folder)

        return

if __name__ == '__main__':
    app = sqlMerge()
    app.main()