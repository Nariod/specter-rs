/// Specter-rs agent plugin — generation UI (AdaptixC2 v1.2 ax dialect).
/// The beacon has no interactive command surface yet (wire lands in phase 3):
/// only the payload generation dialog is exposed.

function RegisterCommands(listenerType)
{
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
