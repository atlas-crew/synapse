//! Terminal User Interface for Synapse-Pingora monitoring.
//! Built with ratatui for high-performance terminal visualization.

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, TableState, Sparkline, Clear, Tabs},
    Frame, Terminal,
};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::System;
use sha2::{Digest, Sha256};
use chrono;
use hex;

use crate::block_log::BlockLog;
use crate::entity::EntityManager;
use crate::metrics::{MetricsRegistry, TuiDataProvider, MetricsSnapshot};
use crate::waf::Synapse;

/// Action that requires operator confirmation
pub enum ConfirmationAction {
    BlockIP(String),
    UnblockIP(String),
    ReloadRules,
}

/// TUI Dashboard Application
pub struct TuiApp {
    /// Data provider for real-time stats
    provider: Arc<dyn TuiDataProvider>,
    /// Last snapshot of metrics
    snapshot: MetricsSnapshot,
    /// Entity manager for risk tracking
    entities: Arc<EntityManager>,
    /// Block log for recent events
    block_log: Arc<BlockLog>,
    /// Shared Synapse engine for rule reloading
    synapse: Arc<parking_lot::RwLock<Synapse>>,
    /// Application start time
    start_time: Instant,
    /// Whether the app should quit
    pub should_quit: bool,
    /// Whether the UI is paused
    pub paused: bool,
    /// Whether to show the help modal
    pub show_help: bool,
    /// Whether to show the entity detail modal
    pub show_entity_detail: bool,
    /// Whether to show the confirmation modal
    pub show_confirmation: bool,
    /// Action to confirm
    pub confirmation_action: Option<ConfirmationAction>,
    /// Active tab index
    pub active_tab: usize,
    /// Whether to show the actor detail modal
    pub show_actor_detail: bool,
    /// System info for resource monitoring
    pub system: System,
    /// Message from last action
    pub last_action_message: Option<String>,
    /// When the message was set
    pub message_time: Option<Instant>,
    /// State for entity table
    pub entity_table_state: TableState,
    /// State for rule table
    pub rule_table_state: TableState,
    /// State for actor table
    pub actor_table_state: TableState,
    /// State for JA4 table
    pub ja4_table_state: TableState,
    /// Last time system info was refreshed
    pub last_system_refresh: Instant,
    /// Tick rate for updates
    tick_rate: Duration,
}

impl TuiApp {
    pub fn new(
        provider: Arc<dyn TuiDataProvider>,
        entities: Arc<EntityManager>,
        block_log: Arc<BlockLog>,
        synapse: Arc<parking_lot::RwLock<Synapse>>,
    ) -> Self {
        Self {
            provider,
            snapshot: MetricsSnapshot::default(),
            entities,
            block_log,
            synapse,
            start_time: Instant::now(),
            should_quit: false,
            paused: false,
            show_help: false,
            show_entity_detail: false,
            show_confirmation: false,
            confirmation_action: None,
            show_actor_detail: false,
            active_tab: 0,
            system: System::new_all(),
            last_action_message: None,
            message_time: None,
            entity_table_state: TableState::default(),
            rule_table_state: TableState::default(),
            actor_table_state: TableState::default(),
            ja4_table_state: TableState::default(),
            last_system_refresh: Instant::now(),
            tick_rate: Duration::from_millis(250),
        }
    }

    /// Run the TUI event loop
    pub fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> io::Result<()> {
        let mut last_tick = Instant::now();
        while !self.should_quit {
            // Update snapshot if not paused
            if !self.paused {
                self.snapshot = self.provider.get_snapshot();
            }

            if !self.paused || self.show_help {
                terminal.draw(|f| self.ui(f))?;
            }

            let timeout = self
                .tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));

            if event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    if self.show_help {
                        match key.code {
                            KeyCode::Char('h') | KeyCode::Char('?') | KeyCode::Esc | KeyCode::Enter => {
                                self.show_help = false;
                            }
                            _ => {}
                        }
                    } else if self.show_entity_detail {
                        match key.code {
                            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                                self.show_entity_detail = false;
                            }
                            _ => {}
                        }
                    } else if self.show_confirmation {
                        match key.code {
                            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                                self.execute_confirmed_action();
                                self.show_confirmation = false;
                            }
                            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                                self.show_confirmation = false;
                                self.confirmation_action = None;
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') => self.should_quit = true,
                            KeyCode::Char('r') => self.provider.reset_all(),
                            KeyCode::Char('p') | KeyCode::Char(' ') => self.paused = !self.paused,
                            KeyCode::Char('?') | KeyCode::Char('h') => self.show_help = !self.show_help,
                            KeyCode::Char('1') => self.active_tab = 0,
                            KeyCode::Char('2') => self.active_tab = 1,
                            KeyCode::Char('3') => self.active_tab = 2,
                            KeyCode::Char('4') => self.active_tab = 3,
                            KeyCode::Tab => {
                                self.active_tab = (self.active_tab + 1) % 4;
                            }
                            KeyCode::Down | KeyCode::Char('j') => self.next_row(),
                            KeyCode::Up | KeyCode::Char('k') => self.previous_row(),
                            KeyCode::Char('u') => self.action_unblock(),
                            KeyCode::Char('b') => self.action_block(),
                            KeyCode::Char('L') => self.action_reload_rules(),
                            KeyCode::Enter => {
                                if self.active_tab == 0 {
                                    self.show_entity_detail = true;
                                } else if self.active_tab == 2 {
                                    self.show_actor_detail = true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            if last_tick.elapsed() >= self.tick_rate {
                // Finding #13: System refresh is expensive, do it every 2 seconds instead of 4 FPS
                if self.last_system_refresh.elapsed() >= Duration::from_secs(2) {
                    self.system.refresh_cpu_all();
                    self.system.refresh_memory();
                    self.last_system_refresh = Instant::now();
                }
                
                // Clear old messages
                if let Some(msg_time) = self.message_time {
                    if msg_time.elapsed() >= Duration::from_secs(3) {
                        self.last_action_message = None;
                        self.message_time = None;
                    }
                }
                
                last_tick = Instant::now();
            }
        }
        Ok(())
    }

    fn set_message(&mut self, message: &str) {
        self.last_action_message = Some(message.to_string());
        self.message_time = Some(Instant::now());
    }

    fn action_unblock(&mut self) {
        if self.active_tab != 0 { return; }
        let selected = self.entity_table_state.selected().unwrap_or(0);
        let top_entities = self.entities.list_top_risk(10);
        if let Some(entity) = top_entities.get(selected) {
            self.confirmation_action = Some(ConfirmationAction::UnblockIP(entity.entity_id.clone()));
            self.show_confirmation = true;
        }
    }

    fn action_block(&mut self) {
        if self.active_tab != 0 { return; }
        let selected = self.entity_table_state.selected().unwrap_or(0);
        let top_entities = self.entities.list_top_risk(10);
        if let Some(entity) = top_entities.get(selected) {
            self.confirmation_action = Some(ConfirmationAction::BlockIP(entity.entity_id.clone()));
            self.show_confirmation = true;
        }
    }

    fn action_reload_rules(&mut self) {
        self.confirmation_action = Some(ConfirmationAction::ReloadRules);
        self.show_confirmation = true;
    }

    fn execute_confirmed_action(&mut self) {
        let action = self.confirmation_action.take();
        match action {
            Some(ConfirmationAction::BlockIP(ip)) => {
                let reason = format!("Manual TUI block at {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
                self.entities.manual_block(&ip, &reason);
                self.set_message(&format!("Blocked IP: {}", ip));
            }
            Some(ConfirmationAction::UnblockIP(ip)) => {
                self.entities.release_entity(&ip);
                self.set_message(&format!("Unblocked IP: {}", ip));
            }
            Some(ConfirmationAction::ReloadRules) => {
                self.perform_reload_rules();
            }
            None => {}
        }
    }

    fn perform_reload_rules(&mut self) {
        // SAFETY: Paths are hardcoded and verified.
        let rules_paths = [
            "data/rules.json",
            "rules.json",
            "/etc/synapse-pingora/rules.json",
        ];

        let mut reloaded = false;
        for path in &rules_paths {
            // Finding #2: Use std::fs::read directly to avoid TOCTOU race
            match std::fs::read(path) {
                Ok(json) => {
                    // Finding #4: Read and parse BEFORE taking the write lock to minimize blocking
                    // Finding #3: Simple integrity check (checksum)
                    let hash = hex::encode(Sha256::digest(&json));
                    
                    // Parse outside of lock
                    match Synapse::parse_rules(&json) {
                        Ok(rules) => {
                            let count = rules.len();
                            let mut synapse = self.synapse.write();
                            match synapse.reload_rules(rules) {
                                Ok(_) => {
                                    drop(synapse);
                                    self.set_message(&format!("Reloaded {} rules (Hash: {}...)", count, &hash[..8]));
                                    reloaded = true;
                                    break;
                                }
                                Err(e) => {
                                    drop(synapse);
                                    self.set_message(&format!("Failed to reload rules: {}", e));
                                    reloaded = true;
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            self.set_message(&format!("Failed to parse rules from {}: {}", path, e));
                            reloaded = true;
                            break;
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                    continue;
                }
                Err(e) => {
                    self.set_message(&format!("Failed to read {}: {}", path, e));
                    reloaded = true;
                    break;
                }
            }
        }

        if !reloaded {
            self.set_message("No rules.json found to reload");
        }
    }

    fn next_row(&mut self) {
        match self.active_tab {
            0 => {
                let len = self.entities.list_top_risk(10).len();
                if len == 0 { return; }
                let i = match self.entity_table_state.selected() {
                    Some(i) => if i >= len.saturating_sub(1) { 0 } else { i + 1 },
                    None => 0,
                };
                self.entity_table_state.select(Some(i));
            }
            1 => {
                let len = self.snapshot.top_rules.len();
                if len == 0 { return; }
                let i = match self.rule_table_state.selected() {
                    Some(i) => if i >= len.saturating_sub(1) { 0 } else { i + 1 },
                    None => 0,
                };
                self.rule_table_state.select(Some(i));
            }
            2 => {
                let len = self.snapshot.top_risky_actors.len();
                if len == 0 { return; }
                let i = match self.actor_table_state.selected() {
                    Some(i) => if i >= len.saturating_sub(1) { 0 } else { i + 1 },
                    None => 0,
                };
                self.actor_table_state.select(Some(i));
            }
            _ => {}
        }
    }

    fn previous_row(&mut self) {
        match self.active_tab {
            0 => {
                let len = self.entities.list_top_risk(10).len();
                if len == 0 { return; }
                let i = match self.entity_table_state.selected() {
                    Some(i) => if i == 0 { len.saturating_sub(1) } else { i - 1 },
                    None => 0,
                };
                self.entity_table_state.select(Some(i));
            }
            1 => {
                let len = self.snapshot.top_rules.len();
                if len == 0 { return; }
                let i = match self.rule_table_state.selected() {
                    Some(i) => if i == 0 { len.saturating_sub(1) } else { i - 1 },
                    None => 0,
                };
                self.rule_table_state.select(Some(i));
            }
            2 => {
                let len = self.snapshot.top_risky_actors.len();
                if len == 0 { return; }
                let i = match self.actor_table_state.selected() {
                    Some(i) => if i == 0 { len.saturating_sub(1) } else { i - 1 },
                    None => 0,
                };
                self.actor_table_state.select(Some(i));
            }
            _ => {}
        }
    }

    fn ui(&mut self, f: &mut Frame) {
        let size = f.size();

        // Vertical layout: Header (3), Tabs (3), Main Content (1fr), Footer (1)
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(10),
                    Constraint::Length(1),
                ]
                .as_ref(),
            )
            .split(size);

        self.render_header(f, chunks[0]);
        self.render_tabs(f, chunks[1]);
        
        match self.active_tab {
            0 => self.render_monitor_tab(f, chunks[2]),
            1 => self.render_waf_tab(f, chunks[2]),
            2 => self.render_intelligence_tab(f, chunks[2]),
            3 => self.render_threat_ops_tab(f, chunks[2]),
            _ => {}
        }
        
        self.render_footer(f, chunks[3]);

        if self.show_help {
            self.render_help_modal(f);
        }

        if self.show_confirmation {
            self.render_confirmation_modal(f);
        }

        if self.show_entity_detail {
            self.render_entity_detail_modal(f);
        }

        if self.show_actor_detail {
            self.render_actor_detail_modal(f);
        }
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let uptime = self.snapshot.uptime_secs;
        let total_requests = self.snapshot.total_requests;
        let blocked = self.snapshot.total_blocked;
        
        let block_rate = if total_requests > 0 {
            (blocked as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        let status_mode = if self.paused {
            " {PAUSED} "
        } else {
            ""
        };

        let header_text = format!(
            " Synapse-Pingora v0.1.0 | Uptime: {}s | Requests: {} | Blocked: {} ({:.1}%){} ",
            uptime, total_requests, blocked, block_rate, status_mode
        );

        let mut header_spans = vec![
            Span::styled(header_text, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ];

        if let Some(ref msg) = self.last_action_message {
            header_spans.push(Span::styled(
                format!(" [ {} ] ", msg),
                Style::default().bg(Color::Yellow).fg(Color::Black).add_modifier(Modifier::BOLD),
            ));
        }

        let header = Paragraph::new(Line::from(header_spans))
            .block(Block::default().borders(Borders::ALL).title(" Status "));
        
        f.render_widget(header, area);
    }

    fn render_tabs(&self, f: &mut Frame, area: Rect) {
        let titles = vec![
            Line::from(" [1] Monitor "),
            Line::from(" [2] WAF & Upstream "),
            Line::from(" [3] Intelligence "),
            Line::from(" [4] Threat Ops "),
        ];
        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::ALL).title(" Navigation "))
            .select(self.active_tab)
            .style(Style::default().fg(Color::White))
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .bg(Color::Cyan)
                    .fg(Color::Black),
            );
        f.render_widget(tabs, area);
    }

    fn render_monitor_tab(&mut self, f: &mut Frame, area: Rect) {
        // Horizontal layout: Left (Metrics + Chart), Right (Entities + Blocks)
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
            .split(area);

        self.render_left_panel(f, main_chunks[0]);
        self.render_right_panel(f, main_chunks[1]);
    }

    fn render_waf_tab(&mut self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(area);

        // Top WAF Rules
        let top_rules = &self.snapshot.top_rules;
        let header = Row::new(vec![
            Cell::from("Rule ID"),
            Cell::from("Hits"),
        ])
        .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Magenta));

        let rows = top_rules.iter().map(|(id, hits)| {
            Row::new(vec![
                Cell::from(id.clone()),
                Cell::from(hits.to_string()),
            ])
        });

        let rule_table = Table::new(
            rows,
            [Constraint::Min(20), Constraint::Length(10)],
        )
        .header(header)
        .highlight_style(Style::default().bg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title(" Top Triggered WAF Rules "));
        
        f.render_stateful_widget(rule_table, chunks[0], &mut self.rule_table_state);

        // Upstream Status
        let backends = &self.snapshot.backend_status;
        let b_header = Row::new(vec![
            Cell::from("Upstream"),
            Cell::from("Status"),
            Cell::from("Reqs"),
            Cell::from("Latency"),
        ])
        .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow));

        let b_rows = backends.iter().map(|(host, m)| {
            let status = if m.healthy { "HEALTHY" } else { "ERROR" };
            let status_color = if m.healthy { Color::Green } else { Color::Red };
            let avg_ms = if m.requests > 0 { m.response_time_us as f64 / m.requests as f64 / 1000.0 } else { 0.0 };
            
            Row::new(vec![
                Cell::from(host.clone()),
                Cell::from(status).style(Style::default().fg(status_color)),
                Cell::from(m.requests.to_string()),
                Cell::from(format!("{:.1}ms", avg_ms)),
            ])
        });

        let backend_table = Table::new(
            b_rows,
            [
                Constraint::Min(20),
                Constraint::Length(10),
                Constraint::Length(8),
                Constraint::Length(10),
            ],
        )
        .header(b_header)
        .block(Block::default().borders(Borders::ALL).title(" Upstream Backend Health "));
        f.render_widget(backend_table, chunks[1]);
    }

    fn render_intelligence_tab(&mut self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
            .split(area);

        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(33),
                Constraint::Percentage(33),
                Constraint::Percentage(34),
            ].as_ref())
            .split(chunks[0]);

        // Legitimate Crawlers
        let crawlers = &self.snapshot.top_crawlers;
        let c_items: Vec<ListItem> = crawlers.iter().map(|(name, hits)| {
            ListItem::new(format!("{:<15} : {} hits", name, hits))
                .style(Style::default().fg(Color::Green))
        }).collect();
        let c_list = List::new(c_items)
            .block(Block::default().borders(Borders::ALL).title(" Legitimate Crawlers "));
        f.render_widget(c_list, left_chunks[0]);

        // Bad Bots
        let bad_bots = &self.snapshot.top_bad_bots;
        let b_items: Vec<ListItem> = bad_bots.iter().map(|(name, hits)| {
            ListItem::new(format!("{:<15} : {} hits", name, hits))
                .style(Style::default().fg(Color::Red))
        }).collect();
        let b_list = List::new(b_items)
            .block(Block::default().borders(Borders::ALL).title(" Malicious Bots / Scrapers "));
        f.render_widget(b_list, left_chunks[1]);

        // DLP Hits
        let dlp_hits = &self.snapshot.top_dlp_hits;
        let d_items: Vec<ListItem> = dlp_hits.iter().map(|(name, hits)| {
            ListItem::new(format!("{:<15} : {} matches", name, hits))
                .style(Style::default().fg(Color::Magenta))
        }).collect();
        let d_list = List::new(d_items)
            .block(Block::default().borders(Borders::ALL).title(" DLP Security Scan "));
        f.render_widget(d_list, left_chunks[2]);

        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(chunks[1]);

        // JA4 clusters
        let clusters = &self.snapshot.top_ja4_clusters;
        let header = Row::new(vec![
            Cell::from("Fingerprint (JA4)"),
            Cell::from("Nodes"),
            Cell::from("Max Risk"),
        ])
        .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan));

        let rows = clusters.iter().map(|(fp, nodes, max_risk)| {
            Row::new(vec![
                Cell::from(fp.clone()),
                Cell::from(nodes.len().to_string()),
                Cell::from(format!("{:.1}", max_risk)),
            ])
        });

        let table = Table::new(
            rows,
            [
                Constraint::Min(30),
                Constraint::Length(8),
                Constraint::Length(10),
            ],
        )
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" JA4 Fingerprint Clusters "));
        f.render_widget(table, right_chunks[0]);

        // Top Risky Actors (Fingerprint correlated)
        let top_actors = &self.snapshot.top_risky_actors;
        let a_header = Row::new(vec![
            Cell::from("Actor ID (Correlated)"),
            Cell::from("Risk"),
            Cell::from("IPs"),
        ])
        .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Red));

        let a_rows = top_actors.iter().map(|actor| {
            Row::new(vec![
                Cell::from(actor.actor_id.clone()),
                Cell::from(format!("{:.1}", actor.risk_score)),
                Cell::from(actor.ips.len().to_string()),
            ])
        });

        let actor_table = Table::new(
            a_rows,
            [
                Constraint::Min(30),
                Constraint::Length(8),
                Constraint::Length(8),
            ],
        )
        .header(a_header)
        .highlight_style(Style::default().bg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title(" Top Correlated Actors "));
        
        f.render_stateful_widget(actor_table, right_chunks[1], &mut self.actor_table_state);
    }

    fn render_threat_ops_tab(&mut self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(area);

        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(chunks[0]);

        // Tarpit Status
        if let Some(ref tarpit) = self.snapshot.tarpit_stats {
            let items = vec![
                ListItem::new(format!("Tracked States: {}", tarpit.total_states)),
                ListItem::new(format!("Active Tarpits: {}", tarpit.active_tarpits)),
                ListItem::new(format!("Total Hits:     {}", tarpit.total_hits)),
                ListItem::new(format!("Total Delay:    {}ms", tarpit.total_delay_ms)),
            ];
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title(" Tarpit Mitigation (Level 4) "));
            f.render_widget(list, left_chunks[0]);
        } else {
            let paragraph = Paragraph::new("\n  Tarpit Manager not initialized.\n  Check configuration to enable Level 4 mitigation.")
                .block(Block::default().borders(Borders::ALL).title(" Tarpit Mitigation (Level 4) "));
            f.render_widget(paragraph, left_chunks[0]);
        }

        // Challenge Stats
        if let Some(ref prog) = self.snapshot.progression_stats {
            let items = vec![
                ListItem::new(format!("Actors Tracked: {}", prog.actors_tracked)),
                ListItem::new(format!("Issued:         {}", prog.challenges_issued)),
                ListItem::new(format!("Success/Fail:   {} / {}", prog.successes, prog.failures)),
                ListItem::new(format!("Escalations:    {}", prog.escalations)),
            ];
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title(" Interrogator Challenges (Level 1-3) "));
            f.render_widget(list, left_chunks[1]);
        } else {
            let paragraph = Paragraph::new("\n  Interrogator System not initialized.\n  Check configuration to enable Level 1-3 challenges.")
                .block(Block::default().borders(Borders::ALL).title(" Interrogator Challenges (Level 1-3) "));
            f.render_widget(paragraph, left_chunks[1]);
        }

        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(chunks[1]);

        // Shadow Mirroring
        if let Some(ref shadow) = self.snapshot.shadow_stats {
            let items = vec![
                ListItem::new(format!("Mirror Mode:   {}", if shadow.enabled { "ACTIVE" } else { "OFF" })),
                ListItem::new(format!("Success:       {}", shadow.delivery_successes)),
                ListItem::new(format!("Failures:      {}", shadow.delivery_failures)),
                ListItem::new(format!("Queue Load:    {}/{}", shadow.max_concurrent - shadow.queue_available, shadow.max_concurrent)),
            ];
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title(" Honeypot Shadow Mirroring "));
            f.render_widget(list, right_chunks[0]);
        } else {
            let paragraph = Paragraph::new("\n  Shadow Mirroring not initialized.\n  Check configuration to enable honeypot mirroring.")
                .block(Block::default().borders(Borders::ALL).title(" Honeypot Shadow Mirroring "));
            f.render_widget(paragraph, right_chunks[0]);
        }

        // Geo Anomalies
        let geo_anomalies = &self.snapshot.recent_geo_anomalies;
        let items: Vec<ListItem> = geo_anomalies.iter().map(|a| {
            ListItem::new(format!("[{:?}] {}", a.severity, a.description))
                .style(Style::default().fg(match a.severity {
                    crate::trends::AnomalySeverity::Critical => Color::Red,
                    crate::trends::AnomalySeverity::High => Color::LightRed,
                    _ => Color::Yellow,
                }))
        }).collect();
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" Geographic / Travel Anomalies "));
        f.render_widget(list, right_chunks[1]);
    }

    fn render_left_panel(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6), // RPS Gauge
                Constraint::Length(6), // Sparkline
                Constraint::Length(6), // Resource Gauges
                Constraint::Min(0)     // Detailed Metrics
            ].as_ref())
            .split(area);

        // RPS Gauge
        let history = &self.snapshot.request_history;
        let rps = history.last().copied().unwrap_or(0);
        let rps_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" Requests/sec "))
            .gauge_style(Style::default().fg(Color::Green))
            .percent((rps.min(100) as u16).into())
            .label(format!("{} RPS", rps));
        f.render_widget(rps_gauge, chunks[0]);

        // Traffic Trend (Sparkline)
        let sparkline = Sparkline::default()
            .block(Block::default().borders(Borders::ALL).title(" Traffic Trend (60s) "))
            .data(history)
            .style(Style::default().fg(Color::Green));
        f.render_widget(sparkline, chunks[1]);

        // System Resource Gauges
        let res_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .margin(1)
            .split(chunks[2]);

        let cpu_usage = self.system.global_cpu_usage();
        let cpu_gauge = Gauge::default()
            .block(Block::default().title(" CPU Usage ").borders(Borders::NONE))
            .gauge_style(Style::default().fg(Color::Yellow))
            .percent(cpu_usage as u16)
            .label(format!("{:.1}%", cpu_usage));
        f.render_widget(cpu_gauge, res_chunks[0]);

        let mem_used = self.system.used_memory() as f64 / 1024.0 / 1024.0 / 1024.0;
        let mem_total = self.system.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0;
        let mem_percent = (mem_used / mem_total * 100.0) as u16;
        let mem_gauge = Gauge::default()
            .block(Block::default().title(" Memory Usage ").borders(Borders::NONE))
            .gauge_style(Style::default().fg(Color::Magenta))
            .percent(mem_percent)
            .label(format!("{:.1}G / {:.1}G", mem_used, mem_total));
        f.render_widget(mem_gauge, res_chunks[1]);

        // Detailed Metrics
        let avg_latency = self.snapshot.avg_latency_ms;
        let avg_waf = self.snapshot.avg_waf_detection_us;
        
        let metrics_list = vec![
            ListItem::new(format!("Avg Latency:   {:.2} ms", avg_latency)),
            ListItem::new(format!("WAF Detection: {:.2} μs", avg_waf)),
            ListItem::new(format!("Active Conns:  {}", self.snapshot.active_requests)),
            ListItem::new(format!("Rules Loaded:  {}", self.snapshot.top_rules.len())),
        ];

        let metrics = List::new(metrics_list)
            .block(Block::default().borders(Borders::ALL).title(" System Metrics "));
        f.render_widget(metrics, chunks[3]);
    }

    fn render_right_panel(&mut self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(area);

        // Top Risky Entities
        let top_entities = self.entities.list_top_risk(10);
        let header = Row::new(vec![
            Cell::from("IP Address"),
            Cell::from("Risk"),
            Cell::from("Reqs"),
            Cell::from("Status"),
        ])
        .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow));

        let rows = top_entities.iter().map(|e| {
            let status = if e.blocked { "BLOCKED" } else { "OK" };
            let status_color = if e.blocked { Color::Red } else { Color::Green };
            let risk_color = if e.risk >= 70.0 {
                Color::Red
            } else if e.risk >= 30.0 {
                Color::Yellow
            } else {
                Color::Green
            };

            Row::new(vec![
                Cell::from(e.entity_id.clone()),
                Cell::from(format!("{:.1}", e.risk)).style(Style::default().fg(risk_color)),
                Cell::from(e.request_count.to_string()),
                Cell::from(status).style(Style::default().fg(status_color)),
            ])
        });

        let table = Table::new(
            rows,
            [
                Constraint::Min(15),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(10),
            ],
        )
        .header(header)
        .highlight_style(Style::default().bg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title(" Top Risky Entities (↑/↓ Select) "));
        
        f.render_stateful_widget(table, chunks[0], &mut self.entity_table_state);

        // Recent Blocks
        let recent_blocks = self.block_log.recent(10);
        let block_items: Vec<ListItem> = recent_blocks
            .iter()
            .map(|b| {
                let time = chrono::DateTime::from_timestamp_millis(b.timestamp as i64)
                    .map(|dt| dt.format("%H:%M:%S").to_string())
                    .unwrap_or_else(|| "00:00:00".to_string());
                
                ListItem::new(format!(
                    "[{}] {} blocked on {} (Risk: {})",
                    time, b.client_ip, b.path, b.risk_score
                ))
                .style(Style::default().fg(Color::Red))
            })
            .collect();

        let blocks = List::new(block_items)
            .block(Block::default().borders(Borders::ALL).title(" Recent WAF Blocks "));
        f.render_widget(blocks, chunks[1]);
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let footer_text = if self.paused {
            " [p] Resume | [q] Quit | [b/u] Block/Unblock | [L] Reload | [Tab] Switch Tab | [h] Help "
        } else {
            " [p] Pause | [q] Quit | [b/u] Block/Unblock | [L] Reload | [Tab] Switch Tab | [h] Help "
        };
        let footer = Paragraph::new(footer_text)
            .style(Style::default().bg(Color::Blue).fg(Color::White));
        f.render_widget(footer, area);
    }

    fn render_help_modal(&self, f: &mut Frame) {
        let area = centered_rect(60, 55, f.size());
        f.render_widget(Clear, area); // Clear the area before rendering the modal

        let help_text = vec![
            Line::from(" Synapse-Pingora TUI Dashboard "),
            Line::from(""),
            Line::from(vec![
                Span::styled("  q           ", Style::default().fg(Color::Yellow)),
                Span::raw(": Quit proxy and dashboard"),
            ]),
            Line::from(vec![
                Span::styled("  p/space     ", Style::default().fg(Color::Yellow)),
                Span::raw(": Pause/Resume UI updates"),
            ]),
            Line::from(vec![
                Span::styled("  Tab / 1-4   ", Style::default().fg(Color::Yellow)),
                Span::raw(": Switch between dashboard tabs"),
            ]),
            Line::from(vec![
                Span::styled("  j/k / ↑/↓   ", Style::default().fg(Color::Yellow)),
                Span::raw(": Navigate through table rows"),
            ]),
            Line::from(vec![
                Span::styled("  b / u       ", Style::default().fg(Color::Yellow)),
                Span::raw(": Manual Block / Unblock selected IP"),
            ]),
            Line::from(vec![
                Span::styled("  L           ", Style::default().fg(Color::Yellow)),
                Span::raw(": Reload rules from disk (Shift+L)"),
            ]),
            Line::from(vec![
                Span::styled("  r           ", Style::default().fg(Color::Yellow)),
                Span::raw(": Reset global statistics"),
            ]),
            Line::from(vec![
                Span::styled("  h/?         ", Style::default().fg(Color::Yellow)),
                Span::raw(": Toggle this help screen"),
            ]),
            Line::from(""),
            Line::from(" Press any key to return "),
        ];

        let help_paragraph = Paragraph::new(help_text)
            .block(Block::default().title(" Help ").borders(Borders::ALL))
            .style(Style::default().fg(Color::White));
        f.render_widget(help_paragraph, area);
    }

    fn render_confirmation_modal(&self, f: &mut Frame) {
        let area = centered_rect(50, 25, f.size());
        f.render_widget(Clear, area);

        let (title, message) = match &self.confirmation_action {
            Some(ConfirmationAction::BlockIP(ip)) => (
                " Confirm Block IP ",
                format!("Are you sure you want to BLOCK traffic from {}?\n\nThis will take immediate effect.", ip),
            ),
            Some(ConfirmationAction::UnblockIP(ip)) => (
                " Confirm Unblock IP ",
                format!("Are you sure you want to UNBLOCK traffic from {}?", ip),
            ),
            Some(ConfirmationAction::ReloadRules) => (
                " Confirm Rule Reload ",
                "Are you sure you want to RELOAD rules from disk?\n\nThis may briefly impact performance during parsing.".to_string(),
            ),
            None => (" Confirmation ", "No action selected.".to_string()),
        };

        let content = vec![
            Line::from(""),
            Line::from(Span::styled(message, Style::default())),
            Line::from(""),
            Line::from(""),
            Line::from(vec![
                Span::styled(" [Y] Yes, proceed ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::raw("   "),
                Span::styled(" [N] No, cancel ", Style::default().fg(Color::Red)),
            ]),
        ];

        let paragraph = Paragraph::new(content)
            .block(Block::default().title(title).borders(Borders::ALL))
            .style(Style::default().fg(Color::White));
        f.render_widget(paragraph, area);
    }

    fn render_entity_detail_modal(&self, f: &mut Frame) {
        let area = centered_rect(70, 60, f.size());
        f.render_widget(Clear, area);

        let top_entities = self.entities.list_top_risk(10);
        let selected_idx = self.entity_table_state.selected().unwrap_or(0);
        
        if let Some(snapshot) = top_entities.get(selected_idx) {
            let mut details = vec![
                Line::from(vec![
                    Span::styled(" Entity ID:    ", Style::default().fg(Color::Cyan)),
                    Span::styled(&snapshot.entity_id, Style::default().add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled(" Risk Score:   ", Style::default().fg(Color::Cyan)),
                    Span::styled(format!("{:.1}", snapshot.risk), Style::default().fg(if snapshot.risk > 70.0 { Color::Red } else { Color::Yellow })),
                ]),
                Line::from(vec![
                    Span::styled(" Total Reqs:   ", Style::default().fg(Color::Cyan)),
                    Span::raw(snapshot.request_count.to_string()),
                ]),
                Line::from(vec![
                    Span::styled(" Status:       ", Style::default().fg(Color::Cyan)),
                    Span::styled(if snapshot.blocked { "BLOCKED" } else { "OK" }, Style::default().fg(if snapshot.blocked { Color::Red } else { Color::Green })),
                ]),
            ];

            if let Some(ref reason) = snapshot.blocked_reason {
                details.push(Line::from(vec![
                    Span::styled(" Block Reason: ", Style::default().fg(Color::Cyan)),
                    Span::styled(reason, Style::default().fg(Color::Gray)),
                ]));
            }

            details.push(Line::from(""));
            details.push(Line::from(" [ Press Enter or Esc to return ] "));

            let paragraph = Paragraph::new(details)
                .block(Block::default().title(" Entity Analysis ").borders(Borders::ALL))
                .style(Style::default().fg(Color::White));
            f.render_widget(paragraph, area);
        }
    }

    fn render_actor_detail_modal(&self, f: &mut Frame) {
        let area = centered_rect(80, 70, f.size());
        f.render_widget(Clear, area);

        let actors = self.metrics.top_risky_actors(10);
        let selected_idx = self.actor_table_state.selected().unwrap_or(0);
        
        if let Some(actor) = actors.get(selected_idx) {
            let mut details = vec![
                Line::from(vec![
                    Span::styled(" Actor ID:     ", Style::default().fg(Color::Cyan)),
                    Span::styled(&actor.actor_id, Style::default().add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled(" Risk Score:   ", Style::default().fg(Color::Cyan)),
                    Span::styled(format!("{:.1}", actor.risk_score), Style::default().fg(if actor.risk_score > 70.0 { Color::Red } else { Color::Yellow })),
                ]),
                Line::from(vec![
                    Span::styled(" IPs:          ", Style::default().fg(Color::Cyan)),
                    Span::raw(actor.ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ")),
                ]),
                Line::from(vec![
                    Span::styled(" Fingerprints: ", Style::default().fg(Color::Cyan)),
                    Span::raw(actor.fingerprints.iter().cloned().collect::<Vec<_>>().join(", ")),
                ]),
                Line::from(vec![
                    Span::styled(" Status:       ", Style::default().fg(Color::Cyan)),
                    Span::styled(if actor.is_blocked { "BLOCKED" } else { "OK" }, Style::default().fg(if actor.is_blocked { Color::Red } else { Color::Green })),
                ]),
                Line::from(""),
                Line::from(Span::styled(" Recent Rule Matches:", Style::default().add_modifier(Modifier::UNDERLINED))),
            ];

            for m in actor.rule_matches.iter().rev().take(5) {
                details.push(Line::from(format!("  - {} ({}) : +{:.1} risk", m.rule_id, m.category, m.risk_contribution)));
            }

            details.push(Line::from(""));
            details.push(Line::from(" [ Press Enter or Esc to return ] "));

            let paragraph = Paragraph::new(details)
                .block(Block::default().title(" Actor Behavior Analysis ").borders(Borders::ALL))
                .style(Style::default().fg(Color::White));
            f.render_widget(paragraph, area);
        }
    }
}

/// Helper function to create a centered rect
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

/// Start the TUI application
pub fn start_tui(
    metrics: Arc<MetricsRegistry>,
    entities: Arc<EntityManager>,
    block_log: Arc<BlockLog>,
    synapse: Arc<parking_lot::RwLock<Synapse>>,
) -> io::Result<()> {
    // Finding #1: Set panic hook to restore terminal on crash
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        original_hook(panic);
    }));

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run
    let mut app = TuiApp::new(metrics, entities, block_log, synapse);
    let res = app.run(&mut terminal);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}