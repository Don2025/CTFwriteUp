# z3-solver求解器

## 简介

`z3-solver`是由`Microsoft Research`开发的`SMT`求解器，它用于检查逻辑表达式的可满足性，可以找到一组约束中的其中一个可行解，缺点是无法找出所有的可行解（对于规划求解问题可以是`scipy`）。

`z3-solver`可应用于软/硬件的验证与测试、约束求解、混合系统的分析、安全、生物，以及几何求解等问题。`Z3`主要由`C++`开发，提供了`.NET`、`C`、`C++`、`Java`、`Python`等语言调用接口。

`z3`可直接通过`pip`安装：

```bash
pip install z3-solver
```

`z3`中有`3`种类型的变量，分别是整数型`Int`、实数型`Real`和向量`BitVec`。

```python
s = Solver()  # 创建一个解的对象
s.add(condition) # 为解对象添加一个限制条件
s.check() #检查解是否存在 若存在则返回sat
s.model() # 输出求解结果
s.assertions() # 查看求解器已添加的约束
```



### 八皇后问题

有一个 `8x8` 的棋盘，希望往里放 `8` 个棋子（皇后），每个棋子所在的行、列、对角线都不能有另一个棋子。如果题目要求找到所有满足条件的解，则只想使用回溯算法进行递归求解，但是如果只需要一个可行解时，则可以使用`z3`求解器。

创建约束条件。

```python
# 每个皇后必须在不同的行中，记录每行对应的皇后对应的列位置
Q = [Int(f'Q_{i}') for i in range(8)]

# 每个皇后在列 0,1,2,...,7
val_c = [And(0 <= Q[i], Q[i] <= 7) for i in range(8)]

# 每列最多一个皇后
col_c = [Distinct(Q)]

# 对角线约束
diag_c = [If(i == j,
             True,
             And(Q[i] - Q[j] != i - j, Q[i] - Q[j] != j - i))
          for i in range(8) for j in range(i)]
```

直接求解可以得到一个可行解中，其中每个皇后的列位置：

```python
solve(val_c + col_c + diag_c)
```

结果：

```python
[Q_3 = 5,
 Q_1 = 1,
 Q_7 = 6,
 Q_5 = 2,
 Q_4 = 0,
 Q_0 = 3,
 Q_2 = 7,
 Q_6 = 4]
```

可以把结果打印得清晰点：

```python
def print_eight_queen(result):
    for column in result:
        for i in range(8):
            if i == column:
                print(end="Q  ")
            else:
                print(end="*  ")
        print()


s = Solver()
s.add(val_c + col_c + diag_c)
if s.check() == sat:
    result = s.model()
    result = [result[Q[i]].as_long() for i in range(8)]
    print("每行皇后所在的列位置：", result)
    print_eight_queen(result)
```

结果：

```python
每行皇后所在的列位置： [5, 3, 1, 7, 4, 6, 0, 2]
*  *  *  *  *  Q  *  *  
*  *  *  Q  *  *  *  *  
*  Q  *  *  *  *  *  *  
*  *  *  *  *  *  *  Q  
*  *  *  *  Q  *  *  *  
*  *  *  *  *  *  Q  *  
Q  *  *  *  *  *  *  *  
*  *  Q  *  *  *  *  * 
```
