import time
import volatility.plugins.common as common
import volatility.win32 as win32
import volatility.utils as utils
import volatility.plugins.taskmods as taskmods
import volatility.plugins.handles as handles
# import volatility.plugins.linux.ldrmodules as ldrmodules
# Skipping due to lack of Plugin for Windows? Only see Mac and Linux
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.vadinfo as vadinfo

start_time = time.time()

class metrics(common.AbstractWindowsCommand):
    def calculate(self):
        start_time = time.time()
        data = []
        addr_space = utils.load_as(self._config)

        #pslist
        tasks_list = list(win32.tasks.pslist(addr_space))
        len_tasks_list = len(tasks_list)
        task_UniqueProcessId = []
        task_InheritedFromUniqueProcessId = []
        total_threads = 0

        for task in tasks_list:
            task_UniqueProcessId.append(task.UniqueProcessId)
            task_InheritedFromUniqueProcessId.append(task.InheritedFromUniqueProcessId)
            total_threads += task.ActiveThreads

        # pslist_nproc
        # Description: Number of processes listed in the pslist plugin
        # Data Type: Integer
        pslist_nproc = len(task_UniqueProcessId)
        data.append(pslist_nproc)


        # pslist_nppid
        # Description: Number of parent process IDs listed in the pslist plugin
        # Data Type: Integer.
        pslist_nppid_nonrepeat = []
        for task in task_InheritedFromUniqueProcessId:
            if task not in pslist_nppid_nonrepeat:
                pslist_nppid_nonrepeat.append(int(task))
        pslist_nppid = len(pslist_nppid_nonrepeat)
        data.append(pslist_nppid)


        # pslist_avg_threads:
        # Description: Average number of threads per process listed in the pslist plugin.
        # Data Type: Float.
        average_threads = total_threads / len_tasks_list
        data.append(average_threads)


        # pslist_nprocs64bit:
        # Description: Number of 64-bit processes listed in the pslist plugin.
        # Data Type: Integer.
        # Skipping this one as the datasets don't have any differences in range (0 - 0)
        data.append(None) # not including in training data

        # pslist_avg_handlers:
        # Description: Average number of handles per process listed in the pslist plugin.
        # Data Type: Float.
        total_handles = 0
        num_processes = 0
        pslist_command = taskmods.PSList(self._config)
        processes = pslist_command.calculate()
        for process in processes:
            num_processes += 1
            for handle in process.ObjectTable.handles():
                if handle.is_valid():
                    total_handles += 1
        average_handles = total_handles / num_processes
        data.append(average_handles)


        # ist_ndlls:
        # Description: Number of DLLs listed in the dlllist plugin.
        # Data Type: Integer.
        dll_list_plugin = taskmods.DllList(self._config)
        dll_list = list(dll_list_plugin.calculate())
        num_dlls = len(dll_list)
        data.append(num_dlls)


        # dlllist_avg_dlls_per_proc:
        # Description: Average number of DLLs per process listed in the dlllist plugin.
        # Data Type: Float
        process_ids = set(entry.UniqueProcessId for entry in dll_list)
        total_dlls = len(dll_list)
        total_processes = len(process_ids)
        average_dlls_per_process = float(total_dlls) / total_processes
        data.append(average_dlls_per_process)


        # handles_nhandles:
        # Description: Total number of handles.
        # Data Type: Integer
        handles_plugin = handles.Handles(self._config)
        handles_data = list(handles_plugin.calculate())
        total_handles = len(handles_data)
        data.append(total_handles)


        # Handles_avg_handles_per_proc:
        # Description: Average number of handles per process.
        # Data Type: Float.
        data.append(average_handles)


        # Handles_nport:
        # Description: Number of port handles.
        # Data Type: Integer
        data.append(None) # not including in training data - all 0



        num_file_handles = 0
        num_event_handles = 0
        num_desktop_handles = 0
        num_key_handles = 0
        num_key_handles = 0
        num_thread_handles = 0
        num_directory_handles = 0
        num_semaphore_handles = 0
        num_timer_handles = 0
        num_section_handles = 0
        num_mutant_handles = 0

        handle_counters = {
            "File": num_file_handles,
            "Event": num_event_handles,
            "Desktop": num_desktop_handles,
            "Key": num_key_handles,
            "Thread": num_thread_handles,
            "Directory": num_directory_handles,
            "Semaphore": num_semaphore_handles,
            "Timer": num_timer_handles,
            "Section": num_section_handles,
            "Mutant": num_mutant_handles,
        }

        for handle_tuple in handles_data:
            object_type = handle_tuple[2]
            if object_type in handle_counters:
                handle_counters[object_type] += 1

        # Handles_nfile:
        # Description: Number of file handles.
        # Data Type: Integer
        data.append(num_file_handles)


        # Handles_nevent:
        # Description: Number of event handles.
        # Data Type: Integer
        data.append(num_event_handles)



        # Handles_ndesktop:
        # Description: Number of desktop handles.
        # Data Type: Integer
        data.append(num_desktop_handles)


        # Handles_nkey:
        # Description: Number of key handles.
        # Data Type: Integer
        data.append(num_key_handles)


        # Handles_nthread:
        # Description: Number of thread handles.
        # Data Type: Integer
        data.append(num_thread_handles)


        # Handles_ndirectory:
        # Description: Number of directory handles.
        # Data Type: Integer
        data.append(num_directory_handles)


        # Handles_nsemaphore:
        # Description: Number of semaphore handles.
        # Data Type: Integer
        data.append(num_semaphore_handles)


        # Handles_ntimer:
        # Description: Number of timer handles.
        # Data Type: Integer
        data.append(num_timer_handles)


        # Handles_nsection:
        # Description: Number of section handles.
        # Data Type: Integer
        data.append(num_section_handles)


        # Handles_nmutant:
        # Description: Number of mutant handles.
        # Data Type: Integer
        data.append(num_mutant_handles)


        # Ldrmodules_not_in_load:
        # Description: Number of modules not in the load phase.
        # Data Type: Integer
        # ldrmodules_plugin = ldrmodules.linux_ldrmodules(self._config)
        # ldrmodules_data = list(ldrmodules_plugin.calculate())
        # num_modules_not_in_load_phase = 0
        # for module_data in ldrmodules_data:
        #     if module_data.InLoadOrderModuleList == 0:
        #         num_modules_not_in_load_phase += 1
        # data.append(num_modules_not_in_load_phase)
        # Skipping due to lack of Plugin for Windows? Only see Mac and Linux
        data.append(None) # not including in training data


        # Ldrmodules_not_in_init:
        # Description: Number of modules not in the init phase.
        # Data Type: Integer
        # Skipping due to lack of Plugin for Windows? Only see Mac and Linux
        data.append(None) # not including in training data


        # Ldrmodules_not_in_mem:
        # Description: Number of modules not in the memory image.
        # Data Type: Integer
        # Skipping due to lack of Plugin for Windows? Only see Mac and Linux
        data.append(None) # not including in training data


        # Ldrmodules_not_in_load_avg:
        # Description: Average number of modules not in the load phase.
        # Data Type: Float
        # Skipping due to lack of Plugin for Windows? Only see Mac and Linux
        data.append(None) # not including in training data


        # Ldrmodules_not_in_init_avg:
        # Description: Average number of modules not in the init phase.
        # Data Type: Float
        # Skipping due to lack of Plugin for Windows? Only see Mac and Linux
        data.append(None) # not including in training data


        # Ldrmodules_not_in_mem_avg:
        # Description: Average number of modules not in the memory image.
        # Data Type: Float
        # Skipping due to lack of Plugin for Windows? Only see Mac and Linux
        data.append(None) # not including in training data


        # Malfind_ninjections:
        # Description: Number of injections found by the malfind plugin.
        # Data Type: Integer
        malfind_plugin = malfind.Malfind(self._config)
        malfind_data = list(malfind_plugin.calculate())
        num_injections = len(malfind_data)
        data.append(num_injections)


        # malfind_commitCharge:
        # Description: Commit charge found by the malfind plugin.
        # Data Type: Integer
        vadinfo_plugin = vadinfo.VADInfo(self._config)
        vadinfo_data = list(vadinfo_plugin.calculate())
        commit_charge = sum(vad.CommitCharge for vad in vadinfo_data if hasattr(vad, 'CommitCharge'))
        data.append(commit_charge)


        # Malfind_protection:
        # Description: Protection found by the malfind plugin.
        # Data Type: Integer
        # protection_info = []
        # for entry in malfind_data:
        #     entry_info = {}
        #     for attr in dir(entry):
        #         entry_info[attr] = getattr(entry, attr)
        #     protection_info.append(entry_info)

            # for entry_info in protection_info:
            #     print(entry_info)
        # data.append(protection_info)


        # malfind_uniqueInjections:
        # Description: Number of unique injections found by the malfind plugin.
        # Data Type: float64















        return data


    def render_text(self, outfd, data):
        labels = [
            'Number of processes listed in the pslist plugin',
            'Number of parent process IDs listed in the pslist plugin',
            'Average number of threads per process listed in the pslist plugin',
            'Number of 64-bit processes listed in the pslist plugin',
            'Average number of handles per process listed in the pslist plugin',
            'Number of DLLs listed in the dlllist plugin',
            'Average number of DLLs per process listed in the dlllist plugin',
            'Total number of handles',
            'Average number of handles per process',
            'Number of port handles',
            'Number of file handles',
            'Number of event handles',
            'Number of desktop handles',
            'Number of key handles',
            'Number of thread handles',
            'Number of directory handles',
            'Number of semaphore handles',
            'Number of timer handles',
            'Number of section handles',
            'Number of mutant handles',
            'Number of modules not in the load phase',
            'Number of modules not in the init phase',
            'Number of modules not in the memory image',
            'Average number of modules not in the load phase',
            'Average number of modules not in the init phase',
            'Average number of modules not in the memory image',
            'Number of injections found by the malfind plugin',
            'Commit charge found by the malfind plugin',
            'Protection found by the malfind plugin',
            'Number of unique injections found by the malfind plugin',
            'Number of processes not in the pslist plugin according to psxview',
            'Number of processes not in the eprocess pool according to psxview',
            'Number of threads not in the ethread pool according to psxview',
            'Number of processes not in the pspcid list according to psxview',
            'Number of processes not in the CSRSS handles according to psxview',
            'Number of processes not in the session according to psxview',
            'Number of processes not in the desktop thread according to psxview',
            'Average number of false positives for processes not in the pslist plugin according to psxview',
            'Average number of false positives for processes not in the eprocess pool according to psxview',
            'Average number of false positives for threads not in the ethread pool according to psxview',
            'Average number of false positives for processes not in the pspcid list according to psxview',
            'Average number of false positives for processes not in the CSRSS handles according to psxview',
            'Average number of false positives for processes not in the session according to psxview',
            'Average number of false positives for processes not in the desktop thread according to psxview',
            'Number of modules',
            'Number of services',
            'Number of kernel drivers',
            'Number of file system drivers',
            'Number of process services',
            'Number of shared process services',
            'Number of interactive process services',
            'Number of active services',
            'Number of callbacks',
            'Number of anonymous callbacks',
            'Number of generic callbacks']

        for label, value in zip(labels, data):
            print "{}: {}".format(label, value)

        print

        results = ', '.join(str(element) for element in data)
        print results

        print

        end_time = time.time()
        elapsed_time = end_time - start_time
        print "Elapsed Time: ", elapsed_time
