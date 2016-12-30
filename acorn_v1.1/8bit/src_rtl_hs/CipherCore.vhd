-------------------------------------------------------------------------------
--! @file       CipherCore.vhd
--! @brief      Cipher core for ACORN128 8-bit version  
--! @author     Tao Huang 
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       Modified based on the template written by Ekawat (ice) Homsirikamol
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.ALL;
use IEEE.NUMERIC_STD.ALL;
use work.AEAD_pkg.ALL;

entity CipherCore is
    generic (
        --! Reset behavior
        G_ASYNC_RSTN    : boolean := False; --! Async active low reset
        --! Block size (bits)
        G_DBLK_SIZE     : integer := 8;   --! Data
        G_KEY_SIZE      : integer := 128;   --! Key
        G_TAG_SIZE      : integer := 128;   --! Tag
        --! The number of bits required to hold block size expressed in
        --! bytes = log2_ceil(G_DBLK_SIZE/8)
        G_LBS_BYTES     : integer := 2; 
        --! Algorithm parameter to simulate run-time behavior
        --! Maximum supported AD/message/ciphertext length = 2^G_MAX_LEN-1
        G_MAX_LEN       : integer := SINGLE_PASS_MAX;
        --! Warning: Do not set any number higher than 32
        G_LAT_KEYINIT   : integer := 1;     --! Key inialization latency
        G_LAT_PREP      : integer := 16;    --! Pre-processing latency (init)
        G_LAT_PROC_AD   : integer := 1;    --! Processing latency (per block)
        G_LAT_PROC_DATA : integer := 1;    --! Processing latency (per block)
        G_LAT_POST      : integer := 8     --! Post-processing latency (tag)
    );
    port (
        --! Global
        clk             : in  std_logic;
        rst             : in  std_logic;
        --! PreProcessor (data)
        key             : in  std_logic_vector(8                -1 downto 0);
        bdi             : in  std_logic_vector(G_DBLK_SIZE      -1 downto 0);
        --! PreProcessor (controls)
        key_ready       : out std_logic;
        key_r_ready     : out std_logic; 
        key_valid       : in  std_logic;
        key_update      : in  std_logic;
        decrypt         : in  std_logic;
        bdi_ready       : out std_logic;
        bdi_valid       : in  std_logic;
        bdi_type        : in  std_logic_vector(3                -1 downto 0);
        bdi_eot         : in  std_logic;
        bdi_eoi         : in  std_logic;
        --! PostProcessor
        bdo             : out std_logic_vector(G_DBLK_SIZE      -1 downto 0);
        bdo_valid       : out std_logic;
        bdo_ready       : in  std_logic;
        msg_auth_done   : out std_logic;
        msg_auth_valid  : out std_logic
    );
end entity CipherCore;

architecture structure of CipherCore is

    --! Registers
    signal key_reg      : std_logic_vector(128              -1 downto 0);
    signal ca           : std_logic_vector(G_DBLK_SIZE      -1 downto 0);
    signal cb           : std_logic_vector(G_DBLK_SIZE      -1 downto 0);
    signal s            : std_logic_vector(293              -1 downto 0);  --! state registers
    signal ks           : std_logic_vector(G_DBLK_SIZE      -1 downto 0);  --! key stream
    signal msg          : std_logic_vector(G_DBLK_SIZE      -1 downto 0);

    --! Signals
    signal s_out        : std_logic_vector(293              -1 downto 0);  --! state registers

    --! Controls
    --!     Register
    signal is_decrypt   : std_logic;
    --!     Combinatorial
    signal ctr          : std_logic_vector(8        -1 downto 0);
    signal ld_key       : std_logic;
    
    signal ld_ctr       : std_logic;
    signal en_ctr       : std_logic;
    signal sel_final    : std_logic;
    signal bdo_valid_r  : std_logic; 
    signal d_msg        : std_logic; 

    --! additional controls 
    signal en_update    : std_logic; 
    signal set_ca_1     : std_logic; 
    signal set_cb_1     : std_logic;
    signal set_ca_0     : std_logic; 
    signal set_cb_0     : std_logic;
    signal decrypt_msg  : std_logic;  
    signal ld_bdi       : std_logic; 
    signal pad_0        : std_logic; 
    signal pad_1        : std_logic; 
    signal cmp_tag      : std_logic; 
    signal auth_fail    : std_logic; 

    ----! additional controls 
    signal set_init     : std_logic; -- set initial state
    signal init_s0      : std_logic; -- stage 0 of initialization
    signal init_s1      : std_logic; -- stage 1 of initialization
    signal init_s2      : std_logic; -- stage 2 of initialization
    signal init_s3      : std_logic; -- stage 3 of initialization
    

    ----signal ud_state_fixm : std_logic; 

    type t_state is (S_INIT, S_WAIT_START, S_WAIT_KEY, S_INIT_STATE, S_INIT_KEY,
        S_WAIT_NPUB, S_INIT_NPUB, S_INIT_REST, S_WAIT_MSG, S_PAD_AD_0, S_PAD_AD, 
        S_PROC_AD, S_PROC_DATA, S_PROC_PT, S_PROC_PT1, S_PROC_PT2, S_PAD_PT0, S_PAD_PT1, S_PRE_FINAL, S_FINAL,
        S_WAIT_TAG_AUTH);
    signal state        : t_state;
    signal nstate       : t_state;

begin
    --! =======================================================================
    --! Datapath
    --! =======================================================================
    process(clk)
    begin
        if rising_edge(clk) then
            if (ld_key = '1') then
                key_reg  <= key & key_reg(127 downto 8);
            end if;

            if (en_update = '1') then 
                s <= s_out; 
            end if; 

            if (set_ca_1 = '1') then 
                ca <= (others => '1'); 
            elsif (set_ca_0 = '1')  then 
                ca <= (others => '0'); 
            end if; 

            if (set_cb_1 = '1') then 
                cb <= (others => '1'); 
            elsif (set_cb_0 = '1') then 
                cb <= (others => '0'); 
            end if;

            if (d_msg = '1') then 
                decrypt_msg <= '1';
            else 
                decrypt_msg <= '0'; 
            end if; 

            if (set_init = '1') then 
                s     <= (others => '0'); 
                msg   <= key_reg(7 downto 0); 
                key_reg <= key_reg(7 downto 0) & key_reg(127 downto 8); 
                auth_fail <= '0';
            elsif (init_s0 = '1') then 
                msg   <= key_reg(7 downto 0); 
                key_reg <= key_reg(7 downto 0) & key_reg(127 downto 8); 
            elsif (init_s1 = '1') then 
                msg   <= bdi; 
            elsif (init_s2 = '1') then
                msg   <= key_reg(7 downto 0) xor (x"01");
                key_reg <= key_reg(7 downto 0) & key_reg(127 downto 8); 
            elsif (init_s3 = '1') then 
                msg   <= key_reg(7 downto 0); 
                key_reg <= key_reg(7 downto 0) & key_reg(127 downto 8); 
            elsif (ld_bdi = '1') then 
                msg   <= bdi; 
            elsif (pad_1 = '1') then 
                msg   <= x"01"; 
            elsif (pad_0 = '1') then 
                msg   <= (others => '0'); 
            end if; 

            if (cmp_tag = '1') then
                if (ks /= bdi) then 
                    auth_fail <= '1'; 
                end if; 
            end if;

            if (bdo_valid_r = '1') then    
                bdo_valid <= '1'; 
            else 
                bdo_valid <= '0'; 
            end if; 

        end if;
    end process;


    msg_auth_valid <= '1' when (auth_fail = '0') else '0';
    bdo <= ks;


    --! =======================================================================
    --! Control
    --! =======================================================================
    gSyncRst:
    if (not G_ASYNC_RSTN) generate
        process(clk)
        begin
            if rising_edge(clk) then
                if (rst = '1') then
                    state <= S_INIT;
                else
                    state <= nstate;
                end if;
            end if;
        end process;
    end generate;

    process(clk)
    begin
        if rising_edge(clk) then
            if (ld_ctr = '1') then
                ctr <= (others => '0');
            elsif (en_ctr = '1') then
                ctr <= std_logic_vector(unsigned(ctr) + 1);
            end if;
            --! Store Decrypt signal internally for use during the tag
            --! authentication state.
            if (state = S_WAIT_START) then
                is_decrypt <= decrypt;
            end if;
        end if;
    end process;

    process(
        state, key_valid, key_update, is_decrypt, ctr,
        bdi_valid, bdi_type, bdi_eot, bdi_eoi,
        bdo_ready)
    begin
        --! Internal
        nstate      <= state;
        ld_key      <= '0';
        ld_ctr      <= '0';
        en_ctr      <= '0';
        set_init    <= '0'; 
        init_s0     <= '0';
        init_s1     <= '0';
        init_s2     <= '0';
        init_s3     <= '0';
        set_ca_1    <= '0';
        set_cb_1    <= '0'; 
        set_ca_0    <= '0';
        set_cb_0    <= '0';
        en_update   <= '0'; 
        ld_bdi      <= '0'; 
        pad_0       <= '0'; 
        pad_1       <= '0'; 
        sel_final   <= '0'; 
        cmp_tag     <= '0'; 
        bdo_valid_r <= '0'; 
        d_msg       <= '0'; 

        --! External
        key_ready   <= '0';
        key_r_ready <= '0'; 
        bdi_ready   <= '0';
        msg_auth_done <= '0';

        case state is
            when S_INIT =>
                --! After reset
                ld_ctr    <= '1';
                nstate <= S_WAIT_START;

            when S_WAIT_START =>
                --! Needs to check whether a new input is available first
                --! prior to checking key to ensure the correct operational
                --! step.
                if (bdi_valid = '1') then
                    if (key_update = '1') then
                        nstate <= S_WAIT_KEY;
                    else
                        nstate <= S_INIT_STATE;
                    end if;
                end if;

            when S_WAIT_KEY =>
                --! Wait for key
                en_ctr <= '1'; 
                if (key_valid = '1') then
                    key_r_ready <= '1';
                    ld_key    <= '1';
                    if (unsigned(ctr) = 15) then 
                        key_ready  <= '1'; 
                        nstate     <= S_INIT_STATE;
                        ld_ctr     <= '1'; 
                    end if; 
                end if;

            when S_INIT_STATE =>
                ld_ctr     <= '1'; 
                set_init   <= '1'; 
                set_ca_1   <= '1'; 
                set_cb_1   <= '1'; 
                nstate     <= S_INIT_KEY; 

            when S_INIT_KEY =>
                en_ctr     <= '1';
                set_ca_1   <= '1'; 
                set_cb_1   <= '1'; 
                en_update  <= '1';
                init_s0    <= '1'; 
                if (unsigned(ctr) = 14) then 
                    nstate <= S_WAIT_NPUB; 
                    ld_ctr <= '1'; 
                end if; 

            when S_WAIT_NPUB =>
                bdi_ready <= '1';
                if (bdi_valid = '1') then    
                    en_update <= '1'; 
                    en_ctr     <= '1';
                    init_s1    <= '1'; 
                    set_ca_1   <= '1';
                    set_cb_1   <= '1';
                    if (unsigned(ctr) = 15) then
                        ld_ctr <= '1'; 
                        nstate  <= S_INIT_REST;
                    end if;
                end if; 

            when S_INIT_REST => 
                en_ctr     <= '1'; 
                set_ca_1   <= '1';
                set_cb_1   <= '1';
                if (unsigned(ctr) = 0) then 
                    init_s2    <= '1';
                    en_update  <= '1';
                elsif (unsigned(ctr) < 192) then 
                    init_s3    <= '1';
                    en_update  <= '1';
                else 
                    nstate <= S_WAIT_MSG; 
                    ld_ctr <= '1';
                end if;

            when S_WAIT_MSG =>
                if (bdi_valid = '1') then
                    if (bdi_type = BDI_TYPE_ASS0) then
                        nstate <= S_PROC_AD;
                    else
                        nstate <= S_PAD_AD_0;
                    end if;
                end if;

            when S_PROC_AD =>
                bdi_ready  <= '1'; 
                set_ca_1   <= '1';
                set_cb_1   <= '1';
                ld_bdi     <= '1';
                en_update  <= '1';
                if (bdi_eot = '1') then 
                    nstate <= S_PAD_AD_0; 
                end if; 

            when S_PAD_AD_0 => 
                en_ctr     <= '1'; 
                pad_1      <= '1'; 
                set_ca_1   <= '1'; 
                set_cb_1   <= '1'; 
                en_update  <= '1';
                nstate     <= S_PAD_AD; 

            when S_PAD_AD => 
                en_ctr <= '1'; 
                if (unsigned(ctr) < 16) then
                    en_update  <= '1';
                    pad_0      <= '1'; 
                    set_ca_1   <= '1'; 
                    set_cb_1   <= '1';

                elsif (unsigned(ctr) < 32) then
                    en_update  <= '1';
                    pad_0      <= '1'; 
                    set_ca_0   <= '1'; 
                    set_cb_1   <= '1';
                else 
                    ld_ctr   <= '1';
                    nstate   <= S_PROC_PT;
                end if;   

            when S_PROC_PT => 
                if (bdi_valid = '1') then 
                    if (bdi_type = BDI_TYPE_DAT0) then
                        nstate <= S_PROC_PT1; 
                    else 
                        nstate <= S_PAD_PT0; 
                    end if; 
                end if; 

            when S_PROC_PT1 => 
                -- assume bdi_valid = '1' 
                bdi_ready  <= '1'; 
                set_ca_1   <= '1';
                set_cb_0   <= '1';
                ld_bdi     <= '1';
                en_update  <= '1';
                bdo_valid_r<= '1'; 
                if (is_decrypt = '1') then 
                    d_msg      <= '1';
                end if; 
                if (bdi_eot = '1') then 
                    nstate <= S_PAD_PT0; 
                end if; 

          when S_PAD_PT0 => 
                en_ctr     <= '1'; 
                pad_1      <= '1'; 
                set_ca_1   <= '1'; 
                set_cb_0   <= '1'; 
                en_update  <= '1';
                nstate     <= S_PAD_PT1;

            when S_PAD_PT1 => 
                en_ctr <= '1'; 
                if (unsigned(ctr) < 16) then
                    en_update  <= '1';
                    pad_0      <= '1'; 
                    set_ca_1   <= '1'; 
                    set_cb_0   <= '1';

                elsif (unsigned(ctr) < 32) then
                    en_update  <= '1';
                    pad_0      <= '1'; 
                    set_ca_0   <= '1'; 
                    set_cb_0   <= '1';
                else 
                    ld_ctr   <= '1';
                    nstate   <= S_FINAL;
                end if; 

            when S_FINAL => 
                if (bdi_type = BDI_TYPE_LEN) then 
                    bdi_ready <= '1';
                end if; 
                sel_final <= '1'; 
                if (unsigned(ctr) < 81) then 
                    en_update  <= '1';
                    en_ctr     <= '1';
                    set_ca_1   <= '1'; 
                    set_cb_1   <= '1';
                    pad_0      <= '1'; 
                    if (unsigned(ctr) = 80) and (is_decrypt = '0') then 
                        bdo_valid_r <= '1';
                    end if; 
                elsif (unsigned(ctr) < 96) then 
                    en_update  <= '1';
                    en_ctr     <= '1';
                    set_ca_1   <= '1'; 
                    set_cb_1   <= '1';
                    pad_0      <= '1'; 
                    if (is_decrypt = '1') then 
                        bdi_ready <= '1';
                        cmp_tag <= '1'; 
                    else 
                        bdo_valid_r <= '1';
                    end if; 
                else 
                    ld_ctr <= '1';
                    if (is_decrypt = '1') then 
                        bdi_ready <= '1'; 
                        nstate <= S_WAIT_TAG_AUTH;
                    else 
                        nstate <= S_INIT; 
                    end if;
                end if; 

                when S_WAIT_TAG_AUTH =>
                    msg_auth_done <= '1';
                    nstate        <= S_INIT;

            when others =>
                null; 
        end case;

    end process;

    state_update: entity work.acorn_stateUpdate8(behavior)
    port map (
                s_in   => s, 
                m_in   => msg, 
                ca     => ca, 
                cb     => cb, 

                is_decrypt => decrypt_msg,

                s_out  => s_out, 
                ks_out => ks 
              );

end structure;

