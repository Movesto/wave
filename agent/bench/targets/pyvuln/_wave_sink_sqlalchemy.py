"""Instrumented-sink oracle for SQLAlchemy (auto-loaded by the wave entry shim).
Logs each SQL statement + bound params BEFORE execution. Grep WAVE-SINK-SQL: a payload that appears
in the STATEMENT (not in PARAMS) proves injection; a bound param proves it was neutralized."""
try:
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    @event.listens_for(Engine, "before_cursor_execute")
    def _wave_log_sql(conn, cursor, statement, parameters, context, executemany):
        print("WAVE-SINK-SQL:: " + repr(statement) + " :: PARAMS=" + repr(parameters), flush=True)
except Exception as _e:
    print("WAVE-SINK-SQL:: (instrumentation failed: %r)" % _e, flush=True)
