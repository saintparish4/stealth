use tree_sitter::Parser;

fn main() {
    // Hardcoded path 
    let file_path = "vulnerable.sol"; // TODO: Make this dynamic

    // Read the Solidity file
    let source_code = match std::fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            std::process::exit(1); 
        }
    };

    // Initialize parser with Solidity grammar
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_solidity::LANGUAGE.into())
        .expect("Error loading Solidity grammar");

    // Parse the source code 
    let tree = match parser.parse(&source_code, None) {
        Some(tree) => tree,
        None => {
            eprintln!("Error parsing Solidity file");
            std::process::exit(1); 
        }
    };

    // Detect reentrancy vulnerabilities 
    detect_reentrancy(&tree, &source_code);
}

fn detect_reentrancy(tree: &tree_sitter::Tree, source_code: &str) {
    let root_node = tree.root_node();
    let mut found_vulnerabilities = false; 

    // Walk through all function defintions
    find_functions(&root_node, source_code, &mut found_vulnerabilities);

    if !found_vulnerabilities {
        println!("No reentrancy vulnerabilities found");
    }
}

fn find_functions(node: &tree_sitter::Node, source_code: &str, found: &mut bool) {
    if node.kind() == "function_definition" {
        check_function_for_reentrancy(node, source_code, found);
    }

    // Recursively check child nodes 
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_functions(&child, source_code, found); 
        }
    }
}

fn check_function_for_reentrancy(function_node: &tree_sitter::Node, source_code: &str, found: &mut bool) {
    // Get function body 
    let body = match find_child_by_kind(function_node, "function_body") {
        Some(b) => b,
        None => return, 
    };

    // Find all statements in the function body 
    let statements = collect_statements(&body);

    // Look for pattern: external call followed by state change
    for (i, stmt) in statements.iter().enumerate() {
        if is_external_call(stmt, source_code) {
            // Check if there are state changes after this call 
            for later_stmt in statements.iter().skip(i + 1) {
                if is_state_change(later_stmt, source_code) {
                    // Found reentrancy vulnerability! 
                    let line = stmt.start_position().row + 1;
                    let state_line = later_stmt.start_position().row + 1;

                    println!("[HIGH] Reentrancy vulnerability at line {}", line);
                    println!(" -> External call at line {}, state change at line {}", line, state_line);
                    println!(" Fix: Move state changes before external call, or add nonReentrant modifier");
                    println!();

                    *found = true;
                    return; // Only report once per function 
                }
            }
        }
    }
}

fn find_child_by_kind<'a>(node: &'a tree_sitter::Node, kind: &str) -> Option<tree_sitter::Node<'a>> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == kind {
                return Some(child);
            }
        }
    }
    None 
}

fn collect_statements<'a>(body: &tree_sitter::Node<'a>) -> Vec<tree_sitter::Node<'a>> {
    let mut statements = Vec::new();
    collect_recursive(body, &mut statements);
    statements 
}

fn collect_recursive<'a>(node: &tree_sitter::Node<'a>, statements: &mut Vec<tree_sitter::Node<'a>>) {
    let kind = node.kind(); 

    // Statements types we care about 
    if kind == "expression_statement"
        || kind == "variable_declaration"
        || kind == "assignment_expression"
        || kind.ends_with("_statement") {
            statements.push(*node); 
        }

        // Recurse into children 
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                collect_recursive(&child, statements); 
            }
        }
}

fn is_external_call(node: &tree_sitter::Node, source_code: &str) -> bool {
    // Check if this node contains .call, .transfer, or .send
    let text = &source_code[node.byte_range()];

    // Look for common external call patterns 
    text.contains(".call{")
    || text.contains(".call(")
    || text.contains(".transfer(")
    || text.contains(".transfer(")
}

fn is_state_change(node: &tree_sitter::Node, source_code: &str) -> bool {
    let text = &source_code[node.byte_range()];

    // Look for state changes (assignments that modify storage)
    // In the vulnerable pattern, we look for -= or += or = operations
    // that modify mappings or state variables 
    if text.contains("balances[") || text.contains("balance[") {
        return text.contains("=") && !text.contains("==");
    }

    // General assignment patterns 
    if node.kind() == "assignment_expression" {
        return true; 
    }

    // Check for -= or += operators which indicate state modification
    text.contains("-=") || text.contains("+=") || text.contains("=") 
}

