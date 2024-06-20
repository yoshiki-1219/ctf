#include<stdio.h>

struct Player
{
    int x;
    int y;
    int live;
};

player_tile = '@';

void clear_screen(void)
{
  printf("\x1b[2J");
  fflush(stdout);
  return;
}

void find_player_pos(char map[30][90], int level)
{
  int x;
  int y;
  
  y = 0;
  do {
    if (29 < y) {
      return;
    }
    for (x = 0; x < 90; x = x + 1) {
      if (map[y][x] == player_tile) {
        printf("Player position: %d %d\n",y,x);
        printf("Level: %d\n", level);
        return;
      }
    }
    y = y + 1;
  } while(1);
}

void find_end_tile_pos(char map[30][90])
{
  int x;
  int y;
  
  y = 0;
  do {
    if (29 < y) {
      return;
    }
    for (x = 0; x < 90; x = x + 1) {
      if (map[y][x] == 'X') {
        printf("End tile position: %d %d\n",y,x);
        return;
      }
    }
    y = y + 1;
  } while(1);
}

void print_lives_left(struct Player *p)
{
  printf("Lives left: %d\n", p->live);
  return;
}

void print_map(char map[30][90], struct Player *p,int *obstacle)
{
  int x;
  int y;
  
  clear_screen();
  find_player_pos(map ,obstacle);
  find_end_tile_pos(map);
  print_lives_left(p);
  for (y = 0; y < 30; y = y + 1) {
    for (x = 0; x < 90; x = x + 1) {
      putchar(map[y][x]);
    }
    putchar('\n');
  }
  fflush(stdout);
  return;
}

void init_map(char map[30][90], struct Player *p,int *obstacle)

{
  int r;
  int x;
  int y;
  
  y = 0;
  do {
    if (29 < y) {
      return;
    }
    for (x = 0; x < 90; x = x + 1) {
      if ((y == 29) && (x == 89)) {
        map[29][89] = 'X';
      }
      else if ((y == p->y) && (x == p->x)) {
        map[y][x] = player_tile;
      }
      else {
        r = rand();
        if (y == r % *obstacle) {
          r = rand();
          if (x == r % *obstacle) {
            map[y][x] = '#';
            continue;
          }
        }
        map[y][x] = '.';
      }
    }
    y = y + 1;
  } while(1);
}

int solve_round(char map[30][90], struct Player *p, int level)
{
  int a;
  
  while (p->x != 89) {
    if (p->x < 89) {
      move_player(p,'d',map,level);
    }
    else {
      move_player(p,'a',map,level);
    }
    print_map(map,p,level);
  }
  while (p->y != 29) {
    if (p->y < 29) {
      move_player(p,'w',map,level);
    }
    else {
      move_player(p,'s',map,level);
    }
    print_map(map,p,level);
  }
  sleep(0);
  a = p->x;
  if (a == 29) {
    a = p->x;
  }
  return a;
}

void move_player(struct Player *p, char move, char map[30][90], int level)
{
  char vuln;
  
  if (p->live < 1) {
    puts("No more lives left. Game over!");
    fflush(stdout);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (move == 'l') {
    vuln = getchar();
    player_tile = vuln;
  }
  if (move == 'p') {
    solve_round(map, p, level);
  }

  map[p->y][p->x] = '.';

  if (move == 'w') {
    p->y = p->y -1;
  }
  else if (move == 's') {
    p->y = p->y + 1;
  }
  else if (move == 'a') {
    p->x = p->x - 1;
  }
  else if (move == 'd') {
    p->x = p->x + 1;
  }

  if (map[p->y][p->x] == '#') {
    puts("You hit an obstacle!");
    fflush(stdout);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  map[p->y][p->x] = player_tile;  //vuln!!!!!!!!!
  p->live = p->live -1;
  return;
}

void main(void)
{
  int c;
  int level;
  struct Player p;
  char map [30][90];
  char move;
  int local_14;

  init_player(&p);
  level = 1;
  local_14 = 0;
  init_map(map,&p,&level);
  print_map(map,&p,&level);
//  signal(2,sigint_handler);
  do {
    c = getchar();
    move = (char)c;
    move_player(&p,(int)move,map,&level);
    print_map(map,&p,&level);
    if (((p.y == 29) && (p.x == 89)) && (level != 4)) { //レベルが４のときは実行されない
      puts("You win!\n Next level starting ");
      local_14 = local_14 + 1;
      level = level + 1;
      init_player(&p);
      init_map(map,&p,&level);
    }
  } while (((p.y != 29) || (p.x != 89)) || ((level != 5 || (local_14 != 4)))); //レベルは５，local_14は４でゴールに到着
  win(&level);
  return 0;
}