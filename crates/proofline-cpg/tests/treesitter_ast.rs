use proofline_cpg::{
    CSourceParser, CpgEdgeKind, CpgNodeKind, GoSourceParser, JavaSourceParser, JsTsSourceParser,
    PythonSourceParser, RustSourceParser,
};

#[test]
fn test_treesitter_c_multiline_and_ignores_comments() {
    let src = r#"
/* Comment trap: fgets(trap, 16, stdin); strcpy(dst, trap); */
int
process_input(
    char *unused,
    int flags
) {
    char buf[128];
    char dst[16];
    fgets(
        buf,
        sizeof(buf),
        stdin
    );
    // Single-line comment trap: system(buf);
    strcpy(
        dst,
        buf
    );
    return 0;
}
"#;

    let cpg = CSourceParser::parse_snippet(src, "multiline.c").expect("C Tree-sitter parse");

    let funcs: Vec<_> = cpg
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            CpgNodeKind::FunctionDef { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(funcs, vec!["process_input"]);

    let sinks: Vec<_> = cpg
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            CpgNodeKind::SecuritySink {
                sink_type,
                target_variable,
            } => Some((sink_type.as_str(), target_variable.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(
        sinks,
        vec![("CWE-119_UNBOUNDED_COPY", "buf")],
        "comments must never produce SecuritySink nodes, and multiline strcpy must link buf"
    );

    assert!(
        cpg.edges
            .iter()
            .any(|e| matches!(&e.kind, CpgEdgeKind::DataFlow { variable } if variable == "buf")),
        "expected DataFlow edge for multiline buf taint flow"
    );
}

#[test]
fn test_treesitter_python_multiline_fstring_and_ignores_comments() {
    let src = r#"
# eval(user_input) in comment should be ignored
def handle_query(
    cursor,
    mode: str = "fast"
):
    uid = request.args.get(
        "uid"
    )
    query = f"SELECT * FROM users WHERE id = '{uid}'"
    cursor.execute(
        query
    )
"#;

    let cpg =
        PythonSourceParser::parse_snippet(src, "multiline.py").expect("Python Tree-sitter parse");

    let ingresses: Vec<_> = cpg
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            CpgNodeKind::SecurityIngress { variable, .. } => Some(variable.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(ingresses, vec!["uid"]);

    let sinks: Vec<_> = cpg
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            CpgNodeKind::SecuritySink { sink_type, .. } => Some(sink_type.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(sinks, vec!["CWE-89_SQL_INJECTION"]);

    assert!(
        cpg.edges
            .iter()
            .any(|e| matches!(&e.kind, CpgEdgeKind::DataFlow { variable } if variable == "uid")),
        "expected DataFlow edge from uid into f-string query assignment"
    );
}

#[test]
fn test_treesitter_rust_multiline_and_command_sink() {
    let src = r#"
// Command::new(ignored) in comment
pub fn run_worker(
    fallback: &str,
) {
    let cmd_arg = std::env::var(
        "TOOL_ARG"
    ).unwrap_or_default();
    Command::new(
        &cmd_arg
    );
}
"#;

    let cpg =
        RustSourceParser::parse_snippet(src, "multiline.rs").expect("Rust Tree-sitter parse");

    let funcs: Vec<_> = cpg
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            CpgNodeKind::FunctionDef { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(funcs, vec!["run_worker"]);

    let sinks: Vec<_> = cpg
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            CpgNodeKind::SecuritySink {
                sink_type,
                target_variable,
            } => Some((sink_type.as_str(), target_variable.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(sinks, vec![("CWE-78_COMMAND_INJECTION", "cmd_arg")]);
}

#[test]
fn test_treesitter_js_ts_go_java_multiline_and_ignores_comments() {
    let ts_src = r#"
/* Comment trap: execSync(fake) */
export async function runHandler(
    req: Request,
    extra: string
) {
    const cmd = req.query.cmd;
    // eval(cmd) in comment must be ignored
    execSync(
        cmd
    );
}
"#;
    let ts_cpg = JsTsSourceParser::parse_snippet(ts_src, "handler.ts").expect("TS parse");
    assert_eq!(ts_cpg.find_ingress_nodes().len(), 1);
    assert_eq!(ts_cpg.find_sink_nodes().len(), 1);

    let go_src = r#"
package main
/* exec.Command("trap") in block comment */
func RunTool(
    r *http.Request,
    mode string,
) {
    cmd := r.URL.Query().Get(
        "cmd",
    )
    // db.Query(cmd) ignored
    exec.Command(
        cmd,
    )
}
"#;
    let go_cpg = GoSourceParser::parse_snippet(go_src, "tool.go").expect("Go parse");
    assert_eq!(go_cpg.find_ingress_nodes().len(), 1);
    assert_eq!(go_cpg.find_sink_nodes().len(), 1);

    let java_src = r#"
class Controller {
    /* stmt.executeQuery(trap) in comment */
    public void handle(
        HttpServletRequest request,
        Statement stmt
    ) {
        String id = request.getParameter(
            "id"
        );
        // Runtime.getRuntime().exec(id) ignored
        stmt.executeQuery(
            id
        );
    }
}
"#;
    let java_cpg = JavaSourceParser::parse_snippet(java_src, "Controller.java").expect("Java parse");
    assert_eq!(java_cpg.find_ingress_nodes().len(), 1);
    assert_eq!(java_cpg.find_sink_nodes().len(), 1);
}
