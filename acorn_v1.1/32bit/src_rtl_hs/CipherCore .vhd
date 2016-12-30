-------------------------------------------------------------------------------
--! @file       CipherCore.vhd
--! @brief      Cipher core for ACORN 32-bit version 
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
        G_DBLK_SIZE     : integer := 32;   --! Data
        G_KEY_SIZE      : integer := 128;   --! Key
        G_TAG_SIZE      : integer := 128;   --! Tag
        --! The number of bits required to hold block size expressed in
        --! bytes = log2_ceil(G_DBLK_SIZE/8)
        G_LBS_BYTES     : integer := 2;
        --! Algorithm parameter to simulate run-time behavior
        --! Maximum supported AD/message/ciphertext length = 2^G_MAX_LEN-1
        G_MAX_LEN       : integer := SINGLE_PASS_MAX
    );
    port (
        --! Global
        clk             : in  std_logic;
        rst             : in  std_logic;
        --! PreProcessor (data)
        key             : in  std_logic_vector(G_KEY_SIZE       -1 downto 0);
        bdi             : in  std_logic_vector(G_DBLK_SIZE      -1 downto 0);
        --! PreProcessor (controls)
        key_ready       : out std_logic;
        key_valid       : in  std_logic;
        key_update      : in  std_logic;
        decrypt         : in  std_logic;
        bdi_ready       : out std_logic;
        bdi_valid       : in  std_logic;
        bdi_type        : in  std_logic_vector(3                -1 downto 0);
        bdi_partial     : in  std_logic;
        bdi_eot         : in  std_logic;
        bdi_eoi         : in  std_logic;
        bdi_size        : in  std_logic_vector(G_LBS_BYTES+1    -1 downto 0);
        bdi_valid_bytes : in  std_logic_vector(G_DBLK_SIZE/8    -1 downto 0);
        bdi_pad_loc     : in  std_logic_vector(G_DBLK_SIZE/8    -1 downto 0);
        --! PostProcessor
        bdo             : out std_logic_vector(G_DBLK_SIZE      -1 downto 0);
        bdo_valid       : out std_logic;
        bdo_ready       : in  std_logic;
        bdo_size        : out std_logic_vector(G_LBS_BYTES+1    -1 downto 0);
        msg_auth_done   : out std_logic;
        msg_auth_valid  : out std_logic
    );
end entity CipherCore;

architecture structure of CipherCore is

    type ARR32 is array (3 downto 0) of std_logic_vector(G_DBLK_SIZE      -1 downto 0);

    --! Registers
    signal bdi_r        : std_logic_vector(G_DBLK_SIZE      -1 downto 0);

    signal key_r        : std_logic_vector(128              -1 downto 0);
    signal ca           : std_logic_vector(G_DBLK_SIZE      -1 downto 0);
    signal cb           : std_logic_vector(G_DBLK_SIZE      -1 downto 0);
    signal tag_rev      : std_logic_vector(G_DBLK_SIZE      -1 downto 0);
    signal s            : std_logic_vector(293              -1 downto 0);  --! state registers
    signal ks           : std_logic_vector(G_DBLK_SIZE      -1 downto 0);  --! key stream
    signal msg          : std_logic_vector(G_DBLK_SIZE      -1 downto 0);
    signal valid_byte_r : std_logic_vector(G_DBLK_SIZE/8    -1 downto 0);
    signal msg_r        : std_logic_vector(24               -1 downto 0);
    signal tmp_msg      : std_logic_vector(24               -1 downto 0); -- store decrypted partial message 

    --! Signals
    signal s_out        : std_logic_vector(293              -1 downto 0);  --! state registers

    --! Controls
    --!     Register
    signal is_decrypt   : std_logic;
    --!     Combinatorial
    signal ctr          : std_logic_vector(6        -1 downto 0);
    signal ld_key       : std_logic;
    signal ld_ctr       : std_logic;
    signal en_ctr       : std_logic;
    signal sel_final    : std_logic;

    --! additional controls 
    signal set_init     : std_logic; -- set initial state
    signal init_s0      : std_logic; -- stage 0 of initialization
    signal init_s1      : std_logic; -- stage 1 of initialization
    signal init_s2      : std_logic; -- stage 2 of initialization
    signal init_s3      : std_logic; -- stage 3 of initialization
    signal pad_ad_s0    : std_logic; 
    signal pad_ad_s1    : std_logic; 
    signal pad_ad_s2    : std_logic; 
    signal pad_pt_s0    : std_logic; 
    signal pad_pt_s1    : std_logic; 
    signal pad_pt_s2    : std_logic; 
    signal final_s      : std_logic; 
    signal auth_fail    : std_logic; 
    signal cmp_tag      : std_logic; -- compare tag 
    signal ad_partial   : std_logic;
    signal ad_full      : std_logic;
    signal pt_partial   : std_logic;
    signal pt_full      : std_logic;
    signal ld_partial_m : std_logic; 
    signal ld_v_byte    : std_logic; 
    signal flag_partial : std_logic; 
    signal out_partial  : std_logic;
    signal decrypt_msg   : std_logic; 


    --signal ud_state_fixm : std_logic; 

    type t_state is (S_INIT, S_WAIT_START, S_WAIT_KEY, S_INIT_KEY,
        S_WAIT_NPUB, S_INIT_STATE, S_INIT_REST, S_WAIT_MSG, S_PAD_AD_0, S_PAD_AD, 
        S_PROC_AD_FULL, S_PROC_AD_PARTIAL, S_PROC_PT, S_PROC_PT_FULL, 
        S_PROC_PT_FULL_OUT, S_PROC_PT_PARTIAL, S_PAD_PT_0,
         S_PAD_PT, S_FINAL,
        S_WAIT_TAG_GEN, S_WAIT_TAG_AUTH);
    signal state        : t_state;
    signal nstate       : t_state;


    function reverse_byte(aa: std_logic_vector) return std_logic_vector is
            variable bb : std_logic_vector(aa'high downto aa'low);
    begin
        for i in ((aa'high+1)/8-1) downto 0 loop
            bb(i*8+7 downto i*8) := aa(aa'high-i*8 downto (aa'high+1)-8-i*8);
        end loop;
        return bb;
    end function reverse_byte;

begin
    --! =======================================================================
    --! Datapath
    --! =======================================================================
    process(clk)
    begin
        if rising_edge(clk) then
            if (ld_key = '1') then
                key_r <= reverse_byte(key);
            end if;

            if (ld_v_byte = '1') then
                valid_byte_r <= bdi_valid_bytes; 
            end if; 

            if (ld_partial_m = '1') then 
                msg_r <= bdi(31 downto 8);
            end if; 

            if (set_init = '1') then 
                s     <= (others => '0'); 
                msg   <= key_r(31 downto 0); 
                key_r <= key_r(31 downto 0) & key_r(127 downto 32); 
                ca    <= (others => '1'); 
                cb    <= (others => '1'); 
                auth_fail <= '0';       -- set initial value of auth_fail to '0'
                flag_partial <= '0'; 
                tmp_msg  <= (others => '0'); 
            elsif (init_s0 = '1') then 
                s     <= s_out; 
                msg   <= key_r(31 downto 0); 
                key_r <= key_r(31 downto 0) & key_r(127 downto 32); 
            elsif (init_s1 = '1') then 
                s     <= s_out; 
                msg   <= reverse_byte(bdi); 
                
            elsif (init_s2 = '1') then
                s     <= s_out; 
                msg   <= key_r(31 downto 0) xor (x"00000001"); 
                key_r <= key_r(31 downto 0) & key_r(127 downto 32); 
            elsif (init_s3 = '1') then 
                s     <= s_out; 
                msg   <= key_r(31 downto 0); 
                key_r <= key_r(31 downto 0) & key_r(127 downto 32); 
            end if; 

            if (pad_ad_s0 = '1') then 
                s <= s_out;
                flag_partial <= '0';
                msg   <= x"00000001"; 
                ca    <= (others => '1');
                cb    <= (others => '1'); 
            elsif (pad_ad_s1 = '1') then
                s     <= s_out;
                msg   <= (others => '0');
                ca    <= (others => '1');
                cb    <= (others => '1'); 
            elsif (pad_ad_s2 = '1') then
                s     <= s_out;
                msg   <= (others => '0');
                ca    <= (others => '0');
                cb    <= (others => '1'); 
            end if; 

            if (final_s = '1') then
                s     <= s_out; 
                decrypt_msg <= '0'; 
                msg   <= (others => '0');
                ca    <= (others => '1');
                cb    <= (others => '1'); 
            end if; 

            if (ad_full = '1') then 
                s     <= s_out; 
                msg   <= reverse_byte(bdi); 
                ca    <= (others => '1');
                cb    <= (others => '1'); 
            end if; 

            if (ad_partial = '1') then 
                flag_partial <= '1'; 
                s <= s_out; 
                msg <= x"000000" & msg_r(23 downto 16); 
                valid_byte_r <= (valid_byte_r(2 downto 0) & "0"); 
                msg_r <= (msg_r(15 downto 0) & "00000000"); 
				ca  <= (others => '1');
                cb  <= (others => '1');                

            end if; 

            if (pt_full = '1') then 
                if (is_decrypt = '1') then 
                    decrypt_msg <= '1'; 
                else 
                    decrypt_msg <= '0'; 
                end if; 
                s     <= s_out; 
                msg   <= reverse_byte(bdi); 
                ca    <= (others => '1');
                cb    <= (others => '0'); 
            end if; 

            if (pt_partial = '1') then 
                s <= s_out; 
                flag_partial <= '1'; 

                if (is_decrypt = '1') then 
                    decrypt_msg <= '1'; 
                else 
                    decrypt_msg <= '0'; 
                end if; 
                msg <= x"000000" & msg_r(23 downto 16); 
                valid_byte_r <= (valid_byte_r(2 downto 0) & "0");
                msg_r <= (msg_r(15 downto 0) & "00000000"); 

                case (to_integer(unsigned(ctr))) is 
                    when 1 => 
                        tmp_msg(23 downto 16) <= ks(7 downto 0); 
                    when 2 => 
                        tmp_msg(15 downto 8)  <= ks(7 downto 0); 
                    when 3 => 
                        tmp_msg(7 downto 0)   <= ks(7 downto 0);
                    when others => 
                        null;
                    end case; 
                ca  <= (others => '1');
                cb  <= (others => '0');
            end if;

            if (pad_pt_s0 = '1') then 
                s <= s_out; 
                flag_partial <= '0'; 
                decrypt_msg <= '0'; 
                msg   <= x"00000001"; 
                ca    <= (others => '1');
                cb    <= (others => '0'); 
            elsif (pad_pt_s1 = '1') then
                s     <= s_out;
                msg   <= (others => '0');
                ca    <= (others => '1');
                cb    <= (others => '0'); 
            elsif (pad_pt_s2 = '1') then
                s     <= s_out;
                msg   <= (others => '0');
                ca    <= (others => '0');
                cb    <= (others => '0'); 
            end if;

            if (out_partial = '1') then 
                case (to_integer(unsigned(ctr))) is 
                    when 1 => 
                        tmp_msg(23 downto 16) <= ks(7 downto 0); 
                    when 2 => 
                        tmp_msg(15 downto 8)  <= ks(7 downto 0); 
                    when 3 => 
                        tmp_msg(7 downto 0)   <= ks(7 downto 0);
                    when others => 
                        null;
                end case;
            end if; 

            if (cmp_tag = '1') then
                if (tag_rev /= bdi) then 
                    auth_fail <= '1'; 
                end if; 
            end if;

        end if;
    end process;

     aBlock: block
        signal vbits : std_logic_vector(G_DBLK_SIZE-1 downto 0);
        signal pad   : std_logic_vector(G_DBLK_SIZE-1 downto 0);
        signal ext   : std_logic_vector(G_DBLK_SIZE-1 downto 0);
    begin
        
        gVbits:
        for i in 0 to G_DBLK_SIZE/8-1 generate
            --! Get valid bits from valid bytes
            vbits(8*i+7 downto 8*i) <= (others => bdi_valid_bytes(i));           
        end generate;

        bdi_r <= reverse_byte(bdi); 
         
    end block;

    tag_rev <= reverse_byte(ks); 

    msg_auth_valid <= '1' when (auth_fail = '0') else '0';
    bdo <= tag_rev when (sel_final = '1') else 
           reverse_byte(ks)      when (flag_partial = '0') else 
           tmp_msg & "00000000";

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
    gAsyncRstn:
    if (G_ASYNC_RSTN) generate
        process(clk, rst)
        begin
            if (rst = '0') then
                state <= S_INIT;
            elsif rising_edge(clk) then
                state <= nstate;
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
        bdi_valid, bdi_type, bdi_eot, bdi_eoi, bdi_size,
        bdo_ready, valid_byte_r)
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
        pad_ad_s0   <= '0';
        pad_ad_s1   <= '0';
        pad_ad_s2   <= '0';
        pad_pt_s0   <= '0';
        pad_pt_s1   <= '0';
        pad_pt_s2   <= '0';
        final_s     <= '0'; 
        cmp_tag     <= '0';
        ad_partial  <= '0';
        ad_full     <= '0';
        pt_partial  <= '0';
        pt_full     <= '0';
        ld_partial_m<= '0';
        ld_v_byte   <= '0';
        out_partial <= '0';
        sel_final   <= '0';

        --set_flag_p  <= '0'; 

        --! External
        key_ready   <= '0';
        bdi_ready   <= '0';
        bdo_valid   <= '0';
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
                if (key_valid = '1') then
                    key_ready <= '1';
                    ld_key    <= '1';
                    nstate    <= S_INIT_STATE;
                end if;

            when S_INIT_STATE => 
                ld_ctr     <= '1'; 
                set_init   <= '1'; 
                nstate     <= S_INIT_KEY; 

            when S_INIT_KEY =>
                en_ctr     <= '1';
                init_s0    <= '1'; 
                if (unsigned(ctr) = 2) then 
                    nstate <= S_WAIT_NPUB; 
                    ld_ctr <= '1'; 
                end if; 

            when S_WAIT_NPUB =>
                bdi_ready <= '1';
                if (bdi_valid = '1') then    
                    en_ctr <= '1';
                    init_s1 <= '1'; 
                    if (unsigned(ctr) = 3) then
                        ld_ctr <= '1'; 
                        nstate  <= S_INIT_REST;
                    end if;
                end if;

            when S_INIT_REST =>
                --! Simulate msg initialization delay
                en_ctr <= '1';
                if (unsigned(ctr) = 0) then
                    init_s2 <= '1'; 
                elsif (unsigned(ctr) < 48) then
                    init_s3 <= '1'; 
                else 
                    ld_ctr <= '1'; 
                    nstate <= S_WAIT_MSG; 
                end if; 

            when S_WAIT_MSG =>
                --! Accumulate AD onto accum register
                if (bdi_valid = '1') then
                    if (bdi_type = BDI_TYPE_ASS0) then
                        --! Note: Assume ST_AD is used (see: AEAD_pkg.vhd)
                        if ((bdi_eot = '0') or ((bdi_eot = '1') and (unsigned(bdi_valid_bytes) = 15))) then 
                            nstate <= S_PROC_AD_FULL;
                        else 
                            ld_v_byte    <= '1';
                            ld_partial_m <= '1'; 
                            nstate <= S_PROC_AD_PARTIAL; 
                        end if; 
                    else
                        nstate <= S_PAD_AD_0;
                    end if;
                end if;

            when S_PROC_AD_FULL =>
                --! Process AD
                if ((bdi_eot = '1') and (unsigned(bdi_valid_bytes) /= 15)) then 
                    ld_v_byte    <= '1';
                    ld_partial_m <= '1'; 
                    nstate <= S_PROC_AD_PARTIAL;
                else 
                    bdi_ready <= '1';
                    ad_full   <= '1';
                    if (bdi_eot = '1') then 
                        nstate <= S_PAD_AD_0;
                    end if; 
                end if; 

            when S_PROC_AD_PARTIAL => 
                if (unsigned(valid_byte_r) = 0) then 
                    bdi_ready <= '1'; 
                    nstate <= S_PAD_AD_0; 
                else 
                    ad_partial <= '1'; 
                end if; 

            when S_PAD_AD_0 => 
                en_ctr <= '1';
                pad_ad_s0 <= '1'; 
                nstate <= S_PAD_AD;

            when S_PAD_AD => 
                en_ctr <= '1'; 
                if (unsigned(ctr) < 4) then
                    pad_ad_s1 <= '1';
                elsif (unsigned(ctr) < 8) then
                    pad_ad_s2 <= '1';
                else 
                    ld_ctr   <= '1';
                    nstate   <= S_PROC_PT;
                end if;                

            when S_PROC_PT => 
                if (bdi_valid = '1') then
                    if (bdi_type = BDI_TYPE_DAT0) then
                        if ((bdi_eot = '0') or ((bdi_eot = '1') and (unsigned(bdi_valid_bytes) = 15))) then 
                            nstate <= S_PROC_PT_FULL;
                        else 
                            ld_v_byte    <= '1';
                            ld_partial_m <= '1'; 
                            nstate <= S_PROC_PT_PARTIAL; 
                        end if; 
                    else
                        en_ctr <= '1';
                        pad_pt_s0 <= '1'; 
                        nstate <= S_PAD_PT;
                    end if;
                end if;

            when S_PROC_PT_FULL => 
                if ((bdi_eot = '1') and (unsigned(bdi_valid_bytes) /= 15)) then 
                    ld_v_byte    <= '1';
                    ld_partial_m <= '1'; 
                    nstate <= S_PROC_PT_PARTIAL;
                else 
                    bdi_ready <= '1';
                    pt_full   <= '1';

                    if (bdi_eot = '1') then 
                        nstate <= S_PAD_PT_0;
                    else 
                        nstate <= S_PROC_PT_FULL_OUT; 
                    end if; 
                end if;

            when S_PROC_PT_FULL_OUT => 
                if ((bdi_eot = '1') and (unsigned(bdi_valid_bytes) /= 15)) then 
                    ld_v_byte    <= '1';
                    ld_partial_m <= '1'; 
                    bdo_valid <= '1'; 
                    nstate <= S_PROC_PT_PARTIAL;
                else 
                    bdi_ready <= '1';
                    pt_full   <= '1';
                    bdo_valid <= '1'; 
                    if (bdi_eot = '1') then 
                        nstate <= S_PAD_PT_0;
                    end if; 
                end if; 

            when S_PROC_PT_PARTIAL => 
                if (unsigned(valid_byte_r) = 0) then 
                    --en_ctr <= '1';
                    ld_ctr <= '1'; 
                    bdi_ready <= '1';
                    out_partial <= '1'; 
                    nstate <= S_PAD_PT_0; 
                else 
                    pt_partial <= '1'; 
                    en_ctr <= '1';
                end if;

            when S_PAD_PT_0 => 
                nstate <= S_PAD_PT;
                --bdi_ready <= '1'; 
                en_ctr <= '1';
                pad_pt_s0 <= '1'; 
                bdo_valid <= '1';

            when S_PAD_PT => 
                en_ctr <= '1'; 
                if (unsigned(ctr) < 4) then
                    pad_pt_s1 <= '1';
                elsif (unsigned(ctr) < 8) then
                    pad_pt_s2 <= '1';
                else 
                    ld_ctr   <= '1';
                    final_s  <= '1';
                    nstate   <= S_FINAL;
                end if;  

            when S_FINAL => 
                if (unsigned(ctr) < 20) then
                    en_ctr <= '1';
                    final_s <= '1';
                    sel_final <= '1';
                elsif (unsigned(ctr) < 24) then
                        sel_final <= '1';
                        final_s <= '1';
                        if (is_decrypt = '1') then
                            en_ctr    <= '1';
                            bdi_ready <= '1'; 
                            cmp_tag   <= '1';
                        else
                            en_ctr    <= '1';
                            bdo_valid <= '1';
                        end if;
                else
                    ld_ctr <= '1';
                    if (is_decrypt = '1') then 
                        nstate <= S_WAIT_TAG_AUTH;
                    else 
                        nstate <= S_INIT; 
                    end if; 
                end if;

            when S_WAIT_TAG_GEN =>
                en_ctr <= '1';
                bdo_valid <= '1';
                if (unsigned(ctr) = 3) then
                    ld_ctr <= '1';
                    nstate <= S_INIT; 
                end if; 

            when S_WAIT_TAG_AUTH =>
                msg_auth_done <= '1';
                nstate        <= S_INIT;
        end case;

    end process;

    state_update: entity work.acorn_stateUpdate32(behavior)
    port map (
                s_in     => s, 
                m_in     => msg, 
                ca       => ca, 
                cb       => cb, 
                is_decrypt => decrypt_msg,
                is_partial => flag_partial,

                s_out    => s_out, 
                ks_out   => ks 
              );

end structure;