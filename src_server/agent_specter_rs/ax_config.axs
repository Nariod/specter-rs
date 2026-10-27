/// Specter-rs agent plugin — generation UI + command dialogs (AdaptixC2 v1.2
/// ax dialect). The group name equals the agent_name (config.yaml):
/// the client offers the commands of the session's agent type.
///
/// Commands the beacon implements (crates/core/src/transport.rs): sleep
/// (COMMAND_PROFILE subop 1) and terminate (COMMAND_TERMINATE). The rest
/// of the native command set lands with the phase 3 task handlers.

function RegisterCommands(listenerType)
{
    let cmd_pwd = ax.create_command("pwd", "Print current working directory", "pwd", "Task: show working directory");

    let cmd_cd = ax.create_command("cd", "Change current working directory", "cd C:\\Windows", "Task: change working directory");
    cmd_cd.addArgString("path", true);

    let cmd_ls = ax.create_command("ls", "List files in a directory", "ls C:\\Users", "Task: list files");
    cmd_ls.addArgString("path", true);

    let cmd_cat = ax.create_command("cat", "Read first 2048 bytes of the specified file", "cat C:\\file.txt", "Task: read file");
    cmd_cat.addArgString("path", true);

    let cmd_mkdir = ax.create_command("mkdir", "Create a directory", "mkdir C:\\Temp\\specter", "Task: create directory");
    cmd_mkdir.addArgString("path", true);

    let cmd_rm = ax.create_command("rm", "Delete a file or an empty directory", "rm C:\\Temp\\specter\\file.txt", "Task: delete");
    cmd_rm.addArgString("path", true);

    let cmd_cp = ax.create_command("cp", "Copy a file", "cp C:\\src.txt C:\\dst.txt", "Task: copy file");
    cmd_cp.addArgString("src", true);
    cmd_cp.addArgString("dst", true);

    let cmd_mv = ax.create_command("mv", "Move a file", "mv C:\\src.txt C:\\dst.txt", "Task: move file");
    cmd_mv.addArgString("src", true);
    cmd_mv.addArgString("dst", true);

    let cmd_getuid = ax.create_command("getuid", "Prints the User ID associated with the current token", "getuid", "Task: get username of current token");

    let cmd_disks = ax.create_command("disks", "Lists mounted drives on current system", "disks", "Task: show mounted disks");

    let _cmd_ps_list = ax.create_command("list", "List of processes", "ps list", "Task: show process list");
    let _cmd_ps_kill = ax.create_command("kill", "Kill a process", "ps kill 1234", "Task: kill process");
    _cmd_ps_kill.addArgInt("pid", true);
    let cmd_ps = ax.create_command("ps", "Process manager");
    cmd_ps.addSubCommands([_cmd_ps_list, _cmd_ps_kill]);

    let cmd_sleep = ax.create_command("sleep", "Sets sleep time", "sleep 30m5s 10", "Task: sleep");
    cmd_sleep.addArgString("sleep", true, "Time in '%h%m%s' format or number of seconds");
    cmd_sleep.addArgInt("jitter", false, "Max random amount of time in % added to sleep");

    let _cmd_terminate_thread = ax.create_command("thread", "Terminate the main beacon thread (without terminating the process)", "terminate thread", "Task: terminate agent thread");
    let _cmd_terminate_process = ax.create_command("process", "Terminate the beacon process", "terminate process", "Task: terminate agent process");
    let cmd_terminate = ax.create_command("terminate", "Terminate the session");
    cmd_terminate.addSubCommands([_cmd_terminate_thread, _cmd_terminate_process]);

    if(listenerType == "BeaconHTTP") {
        let commands_http = ax.create_commands_group("specter-rs", [cmd_pwd, cmd_cd, cmd_ls, cmd_cat, cmd_mkdir, cmd_rm, cmd_cp, cmd_mv, cmd_getuid, cmd_disks, cmd_ps, cmd_sleep, cmd_terminate]);
        return { commands_windows: commands_http }
    }

    return ax.create_commands_group("none", []);
}

function GenerateUI(listeners_type)
{
    let labelFormat = form.create_label("Format:");
    let comboFormat = form.create_combo();
    comboFormat.addItems(["Bin (raw PIC blob)"]);

    let labelSleep = form.create_label("Sleep:");
    let textSleep = form.create_textline("30s");
    textSleep.setPlaceholder("1h 2m 5s");

    let labelJitter = form.create_label("Jitter %:");
    let spinJitter = form.create_spin();
    spinJitter.setRange(0, 100);
    spinJitter.setValue(10);

    let checkKilldate = form.create_check("Set 'killdate'");
    let dateKill = form.create_dateline("dd.MM.yyyy");
    let timeKill = form.create_timeline("HH:mm:ss");

    let checkDebug = form.create_check("Debug (phase 3)");

    let layout = form.create_gridlayout();
    layout.addWidget(labelFormat,   0, 0, 1, 1);
    layout.addWidget(comboFormat,   0, 1, 1, 1);
    layout.addWidget(labelSleep,    1, 0, 1, 1);
    layout.addWidget(textSleep,    1, 1, 1, 1);
    layout.addWidget(labelJitter,  2, 0, 1, 1);
    layout.addWidget(spinJitter,   2, 1, 1, 1);
    layout.addWidget(checkKilldate, 3, 0, 1, 1);
    layout.addWidget(dateKill,     3, 1, 1, 1);
    layout.addWidget(timeKill,     4, 1, 1, 1);
    layout.addWidget(checkDebug,    5, 0, 1, 1);

    let container = form.create_container();
    container.put("format",     comboFormat);
    container.put("sleep",      textSleep);
    container.put("jitter",     spinJitter);
    container.put("is_killdate", checkKilldate);
    container.put("kill_date",  dateKill);
    container.put("kill_time",  timeKill);
    container.put("debug",       checkDebug);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 240,
        ui_width: 420
    }
}
