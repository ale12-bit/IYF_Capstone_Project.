-- =========================================
-- EXTENSIONS
-- =========================================
create extension if not exists "uuid-ossp";

-- =========================================
-- USERS TABLE
-- =========================================
create table users (
  user_id uuid primary key default uuid_generate_v4(),
  username text not null unique,
  email text not null unique,
  password_hash text not null,
  role text check (role in ('admin', 'user')) default 'user',
  profile_info jsonb,
  created_at timestamp default now()
);

-- =========================================
-- RECIPES TABLE
-- =========================================
create table recipes (
  recipe_id uuid primary key default uuid_generate_v4(),
  title text not null,
  description text,
  ingredients jsonb not null,
  steps jsonb not null,
  image_url text,
  tags text[],
  author_id uuid references users(user_id) on delete cascade,
  challenge_id uuid references challenges(challenge_id) on delete set null,
  created_at timestamp default now()
);

-- =========================================
-- COMMENTS TABLE
-- =========================================
create table comments (
  comment_id uuid primary key default uuid_generate_v4(),
  recipe_id uuid references recipes(recipe_id) on delete cascade,
  user_id uuid references users(user_id) on delete cascade,
  content text not null,
  created_at timestamp default now()
);

-- =========================================
-- RATINGS TABLE
-- =========================================
create table ratings (
  rating_id uuid primary key default uuid_generate_v4(),
  recipe_id uuid references recipes(recipe_id) on delete cascade,
  user_id uuid references users(user_id) on delete cascade,
  score int check (score >= 1 and score <= 5),
  created_at timestamp default now(),
  unique (recipe_id, user_id)
);

-- =========================================
-- FAVORITES TABLE
-- =========================================
create table favorites (
  favorite_id uuid primary key default uuid_generate_v4(),
  user_id uuid references users(user_id) on delete cascade,
  recipe_id uuid references recipes(recipe_id) on delete cascade,
  created_at timestamp default now(),
  unique (user_id, recipe_id)
);

-- =========================================
-- CHALLENGES TABLE
-- =========================================
create table challenges (
  challenge_id uuid primary key default uuid_generate_v4(),
  title text not null,
  description text,
  deadline timestamp not null,
  created_at timestamp default now()
);

-- =========================================
-- ACTIVITY LOG TABLE
-- =========================================
create table activity_log (
  log_id uuid primary key default uuid_generate_v4(),
  user_id uuid references users(user_id) on delete set null,
  action text not null,
  target_table text not null,
  target_id uuid,
  timestamp timestamp default now()
);

-- =========================================
-- HELPER FUNCTIONS
-- =========================================
create or replace function is_admin()
returns boolean as $$
  select exists (
    select 1 from users u
    where u.user_id = auth.uid() and u.role = 'admin'
  );
$$ language sql stable;

create or replace function is_owner(target_user uuid)
returns boolean as $$
  select auth.uid() = target_user;
$$ language sql stable;

-- =========================================
-- ENABLE RLS
-- =========================================
alter table users enable row level security;
alter table recipes enable row level security;
alter table comments enable row level security;
alter table ratings enable row level security;
alter table favorites enable row level security;
alter table challenges enable row level security;
alter table activity_log enable row level security;

-- =========================================
-- RLS POLICIES
-- =========================================

-- USERS
create policy "Users can view own profile"
on users for select
using (is_owner(user_id) or is_admin());

create policy "Users can insert own profile"
on users for insert
with check (is_owner(user_id));

create policy "Users can update own profile"
on users for update
using (is_owner(user_id) or is_admin())
with check (is_owner(user_id) or is_admin());

create policy "Users can delete own profile"
on users for delete
using (is_owner(user_id) or is_admin());

-- RECIPES
create policy "Anyone can view recipes"
on recipes for select
using (true);

create policy "Users can insert own recipes"
on recipes for insert
with check (is_owner(author_id));

create policy "Users can update own recipes"
on recipes for update
using (is_owner(author_id) or is_admin())
with check (is_owner(author_id) or is_admin());

create policy "Users can delete own recipes"
on recipes for delete
using (is_owner(author_id) or is_admin());

-- COMMENTS
create policy "Anyone can view comments"
on comments for select
using (true);

create policy "Users can insert own comments"
on comments for insert
with check (is_owner(user_id));

create policy "Users can update own comments"
on comments for update
using (is_owner(user_id) or is_admin())
with check (is_owner(user_id) or is_admin());

create policy "Users can delete own comments"
on comments for delete
using (is_owner(user_id) or is_admin());

-- RATINGS
create policy "Anyone can view ratings"
on ratings for select
using (true);

create policy "Users can insert own ratings"
on ratings for insert
with check (is_owner(user_id));

create policy "Users can update own ratings"
on ratings for update
using (is_owner(user_id) or is_admin())
with check (is_owner(user_id) or is_admin());

create policy "Users can delete own ratings"
on ratings for delete
using (is_owner(user_id) or is_admin());

-- FAVORITES
create policy "Anyone can view favorites"
on favorites for select
using (true);

create policy "Users can insert own favorites"
on favorites for insert
with check (is_owner(user_id));

create policy "Users can delete own favorites"
on favorites for delete
using (is_owner(user_id) or is_admin());

-- CHALLENGES
create policy "Anyone can view challenges"
on challenges for select
using (true);

create policy "Admins can insert challenges"
on challenges for insert
with check (is_admin());

create policy "Admins can update challenges"
on challenges for update
using (is_admin())
with check (is_admin());

create policy "Admins can delete challenges"
on challenges for delete
using (is_admin());

-- ACTIVITY LOG
create policy "Admins can view activity log"
on activity_log for select
using (is_admin());

create policy "System inserts activity logs"
on activity_log for insert
with check (true);

-- =========================================
-- AUDIT LOGGING FUNCTION + TRIGGERS
-- =========================================
create or replace function log_activity()
returns trigger as $$
begin
  insert into activity_log (user_id, action, target_table, target_id, timestamp)
  values (
    auth.uid(),
    TG_OP || '_' || TG_TABLE_NAME,
    TG_TABLE_NAME,
    coalesce(new.recipe_id, new.comment_id, new.rating_id, new.favorite_id, new.user_id, new.challenge_id),
    now()
  );
  return new;
end;
$$ language plpgsql;

-- Attach triggers
create trigger log_users_activity after insert or update or delete on users
for each row execute function log_activity();

create trigger log_recipes_activity after insert or update or delete on recipes
for each row execute function log_activity();

create trigger log_comments_activity after insert or update or delete on comments
for each row execute function log_activity();

create trigger log_ratings_activity after insert or update or delete on ratings
for each row execute function log_activity();

create trigger log_favorites_activity after insert or update or delete on favorites
for each row execute function log_activity();

create trigger log_challenges_activity after insert or update or delete on challenges
for each row execute function log_activity();

-- =========================================
-- SEED DATA
-- =========================================
insert into users (user_id, username, email, password_hash, role, profile_info)
values
  (uuid_generate_v4(), 'alex', 'alex@example.com', 'hashed_pw_123', 'admin', '{"bio":"Founder of MealShare"}'),
  (uuid_generate_v4(), 'mary', 'mary@example.com', 'hashed_pw_456', 'user', '{"bio":"Home cook"}'),
  (uuid_generate_v4(), 'john', 'john@example.com', 'hashed_pw_789', 'user', '{"bio":"Food blogger"}');

insert into challenges (challenge_id, title, description, deadline)
values
  (uuid_generate_v4(), 'Chapati Challenge', 'Share your best chapati recipe', now() + interval '7 days');

insert into recipes (recipe_id, title, description, ingredients, steps, image_url, tags, author_id, challenge_id)
values
  (uuid_generate_v4(), 'Spaghetti Carbonara', 'Classic Italian pasta dish',
   '[{"ingredient":"Spaghetti","amount":"200g"},{"ingredient":"Eggs","amount":"2"},{"ingredient":"Pancetta","amount":"100g"}]'::jsonb,
   '[{"step":"Boil pasta"},{"step":"Cook pancetta"},{"step":"Mix eggs and cheese"},{"step":"Combine all"}]'::jsonb,
   'https://example.com/spaghetti.jpg',
   '{"Italian","Pasta"}',
