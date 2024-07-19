from rich.console import Console
from rich.tree import Tree
import json

# 示例 JSON 数据
data = '''
{
    "name": "Alice",
    "age": 30,
    "city": "New York",
    "children": [
        {
            "name": "Bob",
            "age": 10
        },
        {
            "name": "Charlie",
            "age": 8
        }
    ]
}
'''

# 解析 JSON 数据
parsed_data = json.loads(data)

def add_branch(tree, key, value):
    if isinstance(value, dict):
        branch = tree.add(f"[bold]{key}[/bold]")
        for k, v in value.items():
            add_branch(branch, k, v)
    elif isinstance(value, list):
        branch = tree.add(f"[bold]{key}[/bold]")
        for i, v in enumerate(value):
            add_branch(branch, f"[{i}]", v)
    else:
        tree.add(f"[bold]{key}[/bold]: {value}")

# 创建 Rich 控制台对象
console = Console()

# 创建根树对象
tree = Tree("Root")

# 添加 JSON 数据到树中
for key, value in parsed_data.items():
    add_branch(tree, key, value)

# 打印树状结构
console.print(tree)
