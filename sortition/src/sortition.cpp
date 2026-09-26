#include "../../pilot/include/pilot.hpp"
using namespace eosio;
using std::string;using std::vector;
CONTRACT sortition : public contract {
public:
 using contract::contract;
 TABLE settings {name parent;};using settings_table=singleton<"settings"_n,settings>;
 TABLE state {uint64_t next_cycle=1;uint64_t current=0;uint64_t next_request=1;};using state_table=singleton<"state"_n,state>;
 // phase: snapshot, applications, waiting for grouping, discussion, ballot,
 // runoff, waiting for shortlist, serving, failed, complete.
 TABLE cycle {
  uint64_t id;uint8_t phase=0;pilot::policy rules;uint64_t snapshot=0;uint32_t electorate=0;
  uint32_t closes=0;uint32_t round=0;uint32_t term_ends=0;uint32_t queue_index=0;
  vector<name> pool;vector<name> queue;uint32_t posts=0;string outcome;
  uint64_t primary_key()const{return id;}
 };using cycles_table=multi_index<"cycles"_n,cycle>;
 TABLE candidate {name account;string statement;uint64_t group=0;uint32_t posts=0;uint32_t last_post=0;uint64_t primary_key()const{return account.value;}};using candidates_table=multi_index<"candidates"_n,candidate>;
 TABLE group {uint64_t id;uint32_t round;vector<name> accounts;name nominee;uint64_t primary_key()const{return id;}};using groups_table=multi_index<"groups"_n,group>;
 TABLE ballot {name voter;name nominee;uint64_t group;uint8_t stage;uint64_t primary_key()const{return voter.value;}};using ballots_table=multi_index<"ballots"_n,ballot>;
 TABLE post {uint64_t id;name author;uint64_t group;uint32_t created;string body;uint64_t primary_key()const{return id;}uint64_t by_group()const{return group;}};
 using posts_table=multi_index<"posts"_n,post,indexed_by<"bygroup"_n,const_mem_fun<post,uint64_t,&post::by_group>>>;
 TABLE request {uint64_t id;uint64_t cycle;uint8_t phase;bool fulfilled=false;uint64_t signing_value;checksum256 result;uint64_t primary_key()const{return id;}};using requests_table=multi_index<"requests"_n,request>;
 name parent()const{return settings_table(get_self(),get_self().value).get().parent;}
 ACTION init(name parent) {require_auth(get_self());check(is_account(parent)&&parent!=get_self(),"Invalid parent");settings_table t(get_self(),get_self().value);check(!t.exists(),"Already initialized");t.set({parent},get_self());}
 ACTION start(name member) {
  require_auth(member);auto p=parent();auto cfg=pilot::config(p,p.value).get();check(cfg.sortition==get_self(),"Module not active");check(pilot::eligible(p,member,cfg.rules.kyc),"Not an eligible member");
  state_table st(get_self(),get_self().value);auto s=st.get_or_default();cycles_table t(get_self(),get_self().value);
  if(s.current){auto old=t.get(s.current);check(old.phase>=8,"Finish the current cycle first");}
  auto seat=pilot::seat(p,p.value).get_or_default();check(!seat.holder.value||seat.recalled||pilot::now()>=seat.ends,"Current guardian term still active");
  uint64_t id=s.next_cycle++;s.current=id;st.set(s,get_self());t.emplace(get_self(),[&](auto&r){r.id=id;r.rules=cfg.rules;});
  action(permission_level{get_self(),"active"_n},p,"makesnap"_n,std::make_tuple(get_self(),id,cfg.rules.kyc)).send();
 }
 ACTION snapready(uint64_t reference,uint64_t snapshot,uint32_t count) {require_auth(parent());cycles_table t(get_self(),get_self().value);auto i=t.require_find(reference,"Unknown cycle");check(i->phase==0,"Snapshot already assigned");t.modify(i,same_payer,[&](auto&r){r.snapshot=snapshot;r.electorate=count;r.phase=1;r.closes=pilot::now()+r.rules.applications;});}
 ACTION apply(name candidate,uint64_t cycle_id,string statement) {
  require_auth(candidate);cycles_table t(get_self(),get_self().value);auto c=t.require_find(cycle_id,"Unknown cycle");check(c->phase==1&&pilot::now()<c->closes,"Applications closed");
  check(pilot::in_snapshot(parent(),c->snapshot,candidate),"Not in cycle electorate");check(pilot::eligible(parent(),candidate,c->rules.kyc),"Candidate not currently eligible");
  pilot::custodians custodians(parent(),parent().value);auto existing=custodians.find(candidate.value);auto seat=pilot::seat(parent(),parent().value).get_or_default();
  check(existing==custodians.end() || (seat.holder==candidate&&(seat.recalled||pilot::now()>=seat.ends)),"Permanent guardians cannot apply");
  pilot::bounded_text(statement,2048,"Statement must be 1–2048 bytes");candidates_table a(get_self(),cycle_id);auto old=a.find(candidate.value);
  if(old!=a.end())a.modify(old,same_payer,[&](auto&r){r.statement=statement;});
  else {check(c->pool.size()<pilot::max_candidates,"Pilot supports at most 60 candidates");a.emplace(get_self(),[&](auto&r){r.account=candidate;r.statement=statement;});t.modify(c,same_payer,[&](auto&r){r.pool.push_back(candidate);});}
 }
 ACTION withdraw(name candidate,uint64_t cycle_id) {
  require_auth(candidate);cycles_table t(get_self(),get_self().value);auto c=t.require_find(cycle_id,"Unknown cycle");check(c->phase==1&&pilot::now()<c->closes,"Applications closed");
  candidates_table a(get_self(),cycle_id);a.erase(a.require_find(candidate.value,"Not a candidate"));t.modify(c,same_payer,[&](auto&r){r.pool.erase(std::remove(r.pool.begin(),r.pool.end(),candidate),r.pool.end());});
 }
 ACTION discuss(name author,uint64_t cycle_id,string body) {
  require_auth(author);cycles_table t(get_self(),get_self().value);auto c=t.require_find(cycle_id,"Unknown cycle");check(c->phase==3&&pilot::now()<c->closes,"Discussion window closed");
  candidates_table a(get_self(),cycle_id);auto cand=a.require_find(author.value,"Not a candidate");groups_table g(get_self(),cycle_id);auto group=g.require_find(cand->group,"No assigned group");check(group->round==c->round,"Not assigned this round");
  pilot::bounded_text(body,2048,"Post must be 1–2048 bytes");check(cand->posts<20&&c->posts<1200,"Discussion post limit reached");check(!cand->last_post||pilot::now()>=cand->last_post+30,"Wait 30 seconds between posts");
  posts_table p(get_self(),cycle_id);p.emplace(get_self(),[&](auto&r){r.id=p.available_primary_key();r.author=author;r.group=cand->group;r.created=pilot::now();r.body=body;});
  a.modify(cand,same_payer,[&](auto&r){++r.posts;r.last_post=pilot::now();});t.modify(c,same_payer,[&](auto&r){++r.posts;});
 }
 ACTION vote(name voter,uint64_t cycle_id,name nominee) {
  require_auth(voter);cycles_table t(get_self(),get_self().value);auto c=t.require_find(cycle_id,"Unknown cycle");check((c->phase==4||c->phase==5)&&pilot::now()<c->closes,"Ballot window closed");check(voter!=nominee,"Self voting is prohibited");
  candidates_table a(get_self(),cycle_id);auto cand=a.require_find(voter.value,"Not a candidate");groups_table g(get_self(),cycle_id);auto group=g.require_find(cand->group,"No assigned group");
  check(group->round==c->round&&!group->nominee.value,"Group ballot is already final");check(std::find(group->accounts.begin(),group->accounts.end(),nominee)!=group->accounts.end(),"Nominee not in your group");
  ballots_table b(get_self(),cycle_id);auto old=b.find(voter.value);
  if(old==b.end())b.emplace(get_self(),[&](auto&r){r.voter=voter;r.nominee=nominee;r.group=group->id;r.stage=c->phase;});
  else b.modify(old,same_payer,[&](auto&r){r.nominee=nominee;r.group=group->id;r.stage=c->phase;});
 }
 static uint32_t draw(checksum256 seed,uint32_t& counter,uint32_t bound) {
  uint32_t threshold=uint32_t(-bound)%bound;
  for(;;){auto packed=pack(std::make_tuple(seed,counter++));auto h=sha256(packed.data(),packed.size()).extract_as_byte_array();uint32_t v=uint32_t(h[0])|(uint32_t(h[1])<<8)|(uint32_t(h[2])<<16)|(uint32_t(h[3])<<24);if(v>=threshold)return v%bound;}
 }
 void randomize(uint64_t id,bool shortlist) {
  state_table st(get_self(),get_self().value);auto s=st.get();uint64_t rid=s.next_request++;st.set(s,get_self());
  auto bytes=pack(std::make_tuple(get_self(),rid,id));auto hash=sha256(bytes.data(),bytes.size()).extract_as_byte_array();uint64_t signing=0;for(uint32_t i=0;i<8;++i)signing|=uint64_t(hash[i])<<(i*8);
  cycles_table t(get_self(),get_self().value);auto c=t.require_find(id,"Unknown cycle");uint8_t phase=shortlist?6:2;t.modify(c,same_payer,[&](auto&r){r.phase=phase;});
  requests_table req(get_self(),get_self().value);req.emplace(get_self(),[&](auto&r){r.id=rid;r.cycle=id;r.phase=phase;r.signing_value=signing;});
  action(permission_level{get_self(),"active"_n},"rng"_n,"requestrand"_n,std::make_tuple(rid,signing,get_self())).send();
 }
 ACTION receiverand(uint64_t assoc_id,checksum256 random_value) {
  require_auth("rng"_n);requests_table req(get_self(),get_self().value);auto job=req.require_find(assoc_id,"Unknown RNG request");check(!job->fulfilled,"RNG request already fulfilled");
  cycles_table t(get_self(),get_self().value);auto c=t.require_find(job->cycle,"Unknown cycle");check(c->phase==job->phase&&(c->phase==2||c->phase==6),"Stale RNG callback");
  auto pool=c->pool;uint32_t counter=0;for(uint32_t n=pool.size();n>1;--n)std::swap(pool[n-1],pool[draw(random_value,counter,n)]);
  req.modify(job,same_payer,[&](auto&r){r.fulfilled=true;r.result=random_value;});
  if(c->phase==6) {t.modify(c,same_payer,[&](auto&r){r.queue=pool;r.queue_index=0;r.phase=7;});appoint(c->id,false);return;}
  check(pool.size()>=6,"Not enough candidates for groups");uint32_t count=pool.size()/3,base=pool.size()/count,extra=pool.size()%count,offset=0;uint32_t round=c->round+1;
  groups_table g(get_self(),c->id);candidates_table candidates(get_self(),c->id);
  for(uint32_t j=0;j<count;++j){uint64_t gid=uint64_t(round)*100+j;uint32_t n=base+(j<extra?1:0);vector<name> members(pool.begin()+offset,pool.begin()+offset+n);offset+=n;
    g.emplace(get_self(),[&](auto&r){r.id=gid;r.round=round;r.accounts=members;});
    for(auto account:members){auto a=candidates.require_find(account.value,"Candidate missing");candidates.modify(a,same_payer,[&](auto&r){r.group=gid;});}
  }
  t.modify(c,same_payer,[&](auto&r){r.pool=pool;r.round=round;r.phase=3;r.closes=pilot::now()+r.rules.discussion;});
 }
 void failed(uint64_t id,const string& why) {cycles_table t(get_self(),get_self().value);auto c=t.require_find(id,"Unknown cycle");t.modify(c,same_payer,[&](auto&r){r.phase=8;r.outcome=why;});}
 void appoint(uint64_t id,bool replacement) {
  cycles_table t(get_self(),get_self().value);auto c=t.require_find(id,"Unknown cycle");auto cfg=pilot::config(parent(),parent().value).get();
  uint32_t idx=c->queue_index;name next;
  while(idx<c->queue.size()){auto n=c->queue[idx++];if(pilot::eligible(parent(),n,c->rules.kyc)) {pilot::custodians cust(parent(),parent().value);auto existing=cust.find(n.value);auto old=pilot::seat(parent(),parent().value).get_or_default();if(existing==cust.end()||old.holder==n){next=n;break;}}}
  uint32_t ends=replacement?c->term_ends:pilot::now()+c->rules.term;
  if(replacement&&ends<=pilot::now())ends=pilot::now()+c->rules.term;
  t.modify(c,same_payer,[&](auto&r){r.queue_index=idx;r.term_ends=next.value?ends:0;if(!next.value){r.phase=9;r.outcome="Shortlist exhausted; open a fresh cycle";}});
  action(permission_level{get_self(),"active"_n},parent(),"setseat"_n,std::make_tuple(next,id,next.value?ends:0,c->snapshot)).send();
  if(!next.value) {
    // Exhaustion opens the next application window without requiring a keeper
    // with membership. Empty electorates can recover through normal registration.
    pilot::members members(parent(),parent().value);bool any=false;
    for(auto&m:members)if(!cfg.rules.kyc||pilot::kyced(m.account)){any=true;break;}
    if(any){state_table st(get_self(),get_self().value);auto state=st.get();uint64_t next_id=state.next_cycle++;state.current=next_id;st.set(state,get_self());t.emplace(get_self(),[&](auto&r){r.id=next_id;r.rules=cfg.rules;});action(permission_level{get_self(),"active"_n},parent(),"makesnap"_n,std::make_tuple(get_self(),next_id,cfg.rules.kyc)).send();}
  }
 }
 ACTION advance(uint64_t cycle_id) {
  cycles_table t(get_self(),get_self().value);auto c=t.require_find(cycle_id,"Unknown cycle");
  if(c->phase==0||c->phase==2||c->phase==6||c->phase>=8)return;
  if(c->phase==7){auto seat=pilot::seat(parent(),parent().value).get_or_default();if(!seat.recalled&&pilot::now()<seat.ends)return;appoint(cycle_id,seat.recalled);return;}
  if(pilot::now()<c->closes)return;
  if(c->phase==1){vector<name> pool;for(auto n:c->pool)if(pilot::eligible(parent(),n,c->rules.kyc))pool.push_back(n);if(pool.size()<6){failed(cycle_id,"Fewer than six eligible candidates");return;}t.modify(c,same_payer,[&](auto&r){r.pool=pool;});randomize(cycle_id,false);return;}
  if(c->phase==3){t.modify(c,same_payer,[&](auto&r){r.phase=4;r.closes=pilot::now()+r.rules.ballot;});return;}
  groups_table groups(get_self(),cycle_id);ballots_table votes(get_self(),cycle_id);bool unresolved=false;vector<name> nominees;
  for(auto g=groups.begin();g!=groups.end();++g){if(g->round!=c->round)continue;name winner=g->nominee;
    if(!winner.value)for(auto candidate:g->accounts){uint32_t count=0;for(auto voter:g->accounts){auto b=votes.find(voter.value);if(b!=votes.end()&&b->group==g->id&&b->stage==c->phase&&b->nominee==candidate)++count;}if(count>g->accounts.size()/2){winner=candidate;break;}}
    if(winner.value){if(!g->nominee.value)groups.modify(g,same_payer,[&](auto&r){r.nominee=winner;});nominees.push_back(winner);}else unresolved=true;
  }
  if(unresolved&&c->phase==4){t.modify(c,same_payer,[&](auto&r){r.phase=5;r.closes=pilot::now()+r.rules.ballot;});return;}
  if(nominees.size()<2){failed(cycle_id,"Fewer than two groups selected nominees");return;}
  t.modify(c,same_payer,[&](auto&r){r.pool=nominees;});randomize(cycle_id,nominees.size()<=5);
 }
};
